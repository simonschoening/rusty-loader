// Copyright (c) 2018 Colin Finck, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub mod bootinfo;
pub mod physicalmem;
pub mod serial;
pub mod paging;
pub mod stack;
pub mod irq;
pub mod addr;

use crate::arch::paging::*;
use crate::arch::stack::BOOT_STACK;
//use crate::arch::riscv::irq;
pub use self::bootinfo::*;
use crate::arch::riscv::serial::SerialPort;
use core::convert::TryInto;
use core::intrinsics::copy;
use core::{mem, slice, str};
use goblin::elf;
use hermit_dtb::Dtb;

global_asm!(include_str!("head.S"));

extern "C" {
	static kernel_end: u8;
}

// CONSTANTS
pub const ELF_ARCH: u16 = elf::header::EM_RISCV;

pub const KERNEL_STACK_SIZE: usize = 32_768;
// const SERIAL_PORT_ADDRESS: u16 = 0x3F8;
// const SERIAL_PORT_BAUDRATE: u32 = 115200;

// VARIABLES
static COM1: SerialPort = SerialPort::new();
pub static mut BOOT_INFO: BootInfo = BootInfo::new();
static mut DTB_PTR: usize = 0x82200000;
static mut INITIAL_HART_ID: usize = usize::MAX;
static mut MEM_SIZE: u64 = 0;
static mut MEM_BASE: u64 = 0;
static mut TIMEBASE_FREQ: u64 = 0;
static mut INITRD_START: u64 = 0;
static mut INITRD_END: u64 = 0;

//Each set bit indicates an available hart
static mut HART_MASK: u64 = 0;

// fn paddr_to_slice<'a>(p: multiboot::PAddr, sz: usize) -> Option<&'a [u8]> {
// 	unsafe {
// 		let ptr = mem::transmute(p);
// 		Some(slice::from_raw_parts(ptr, sz))
// 	}
// }

// FUNCTIONS
pub fn message_output_init() {
	COM1.init();
}

pub fn output_message_byte(byte: u8) {
	COM1.write_byte(byte);
}

pub unsafe fn find_kernel() -> &'static [u8] {
	loaderlog!("DTB_PTR: {:x}", DTB_PTR);
	loaderlog!("INITIAL_HART_ID: {}", INITIAL_HART_ID);
	let dtb = Dtb::from_raw(DTB_PTR as *const u8).expect("DTB is invalid");

	//loaderlog!("OK2");

	let memory_reg = dtb.get_property("memory", "reg").expect("Memory node not found in dtb");
	let timebase_data = dtb.get_property("cpus", "timebase-frequency").expect("timebase-frequency node not found in /cpus");
	let initrd_start = dtb.get_property("chosen", "linux,initrd-start").expect("linux,initrd-start node not found in /chosen");
	let initrd_end = dtb.get_property("chosen", "linux,initrd-end").expect("linux,initrd-end node not found in /chosen");
	//loaderlog!("OK3");

	for i in (memory_reg.len()/2)..(memory_reg.len()) {
		MEM_SIZE <<= 8;
		MEM_SIZE += memory_reg[i] as u64;
	}

	for i in 0..(memory_reg.len()/2) {
		MEM_BASE <<= 8;
		MEM_BASE += memory_reg[i] as u64;
	}

	for i in 0..(timebase_data.len()) {
		TIMEBASE_FREQ <<= 8;
		TIMEBASE_FREQ += timebase_data[i] as u64;
	}

	for i in 0..(initrd_start.len()) {
		INITRD_START <<= 8;
		INITRD_START += initrd_start[i] as u64;
	}

	for i in 0..(initrd_end.len()) {
		INITRD_END <<= 8;
		INITRD_END += initrd_end[i] as u64;
	}

	loaderlog!("mem_base: {:x}, mem_size: {:x}, timebase-freq: {}", MEM_BASE, MEM_SIZE, TIMEBASE_FREQ);	

	loaderlog!(
		"Found initrd: [0x{:x} - 0x{:x}]",
		INITRD_START,
		INITRD_END
	);

	for node in dtb.enum_subnodes("cpus") {
		let path = &["cpus/", node].concat();
		let mut device_type_option = dtb.get_property(path, "device_type");
		if let Some(device_type) = device_type_option {
			if let Ok(string) = str::from_utf8(device_type) {
				if string == "cpu\u{0}" {
					let mut status_option = dtb.get_property(path, "status");
					let status = if let Some(status) = status_option {
						if let Ok(string) = str::from_utf8(status) {
							string
						}
						else {
							panic!("Invalid status in cpus/{:?}", node);
						}
					}
					else {
						"unknown"
					};

					let hart_id_slices = dtb.get_property(path, "reg").expect("Missing hart_id in DTB");

					let mut hart_id = 0;
					for i in 0..(hart_id_slices.len()) {
						hart_id <<= 8;
						hart_id += hart_id_slices[i] as u64;
					}

					if status != "disabled\u{0}" {
						HART_MASK |= 1 << hart_id;
					}

					loaderlog!("{:?}, status: {} , hart_id {}", node, status, hart_id);
				}
			}
		}
	} 
	
	// // Identity-map the Multiboot information.
	// assert!(mb_info > 0, "Could not find Multiboot information");
	// loaderlog!("Found Multiboot information at 0x{:x}", mb_info);
	// let page_address = align_down!(mb_info, BasePageSize::SIZE);
	// paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::WRITABLE);

	// // Load the Multiboot information and identity-map the modules information.
	// let multiboot = Multiboot::new(mb_info as u64, paddr_to_slice).unwrap();
	// let modules_address = multiboot
	// 	.modules()
	// 	.expect("Could not find a memory map in the Multiboot information")
	// 	.next()
	// 	.expect("Could not find first map address")
	// 	.start as usize;
	// let page_address = align_down!(modules_address, BasePageSize::SIZE);
	// paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::empty());

	// // Iterate through all modules.
	// // Collect the start address of the first module and the highest end address of all modules.
	// let modules = multiboot.modules().unwrap();
	// let mut found_module = false;
	// let mut start_address = 0;
	// let mut end_address = 0;

	// for m in modules {
	// 	found_module = true;

	// 	if start_address == 0 {
	// 		start_address = m.start as usize;
	// 	}

	// 	if m.end as usize > end_address {
	// 		end_address = m.end as usize;
	// 	}
	// }

	// loaderlog!(
	// 	"Found module: [0x{:x} - 0x{:x}]",
	// 	start_address,
	// 	end_address
	// );
	// let elf_start = start_address;
	// let elf_len = end_address - start_address;
	// loaderlog!("Module length: 0x{:x}", elf_len);

	// // Memory after the highest end address is unused and available for the physical memory manager.
	physicalmem::init(align_up!(INITRD_END as usize, LargePageSize::SIZE));

	// // Identity-map the ELF header of the first module.
	// assert!(
	// 	found_module,
	// 	"Could not find a single module in the Multiboot information"
	// );
	// assert!(start_address > 0);
	// loaderlog!("Found an ELF module at 0x{:x}", start_address);
	// let page_address = align_down!(start_address, BasePageSize::SIZE);
	// let counter =
	// 	(align_up!(start_address, LargePageSize::SIZE) - page_address) / BasePageSize::SIZE;
	// loaderlog!(
	// 	"Map {} pages at 0x{:x} (page size {} KByte)",
	// 	counter,
	// 	page_address,
	// 	BasePageSize::SIZE / 1024
	// );
	// paging::map::<BasePageSize>(
	// 	page_address,
	// 	page_address,
	// 	counter,
	// 	PageTableEntryFlags::empty(),
	// );

	// // map also the rest of the module
	// let address = align_up!(start_address, LargePageSize::SIZE);
	// let counter = (align_up!(end_address, LargePageSize::SIZE) - address) / LargePageSize::SIZE;
	// if counter > 0 {
	// 	loaderlog!(
	// 		"Map {} pages at 0x{:x} (page size {} KByte)",
	// 		counter,
	// 		address,
	// 		LargePageSize::SIZE / 1024
	// 	);
	// 	paging::map::<LargePageSize>(address, address, counter, PageTableEntryFlags::WRITABLE);
	// }

	//panic!("...");

	slice::from_raw_parts(INITRD_START as *const u8, (INITRD_END - INITRD_START) as usize)
}

pub unsafe fn boot_kernel(address: u64, mem_size: u64, entry_point: u64) -> ! {
	// let new_addr = align_up!(&kernel_end as *const u8 as usize, LargePageSize::SIZE) as u64;

	// // copy app to the new start address
	// copy(
	// 	virtual_address as *const u8,
	// 	new_addr as *mut u8,
	// 	mem_size.try_into().unwrap(),
	// );

	// Supply the parameters to the HermitCore application.
	BOOT_INFO.base = address;
	BOOT_INFO.image_size = mem_size;
	//BOOT_INFO.mb_info = mb_info as u64;
	BOOT_INFO.current_stack_address = &BOOT_STACK as *const _ as u64;

	BOOT_INFO.mem_base = MEM_BASE;
	BOOT_INFO.limit = MEM_SIZE;
	BOOT_INFO.timebase_freq = TIMEBASE_FREQ;
	BOOT_INFO.hart_mask = HART_MASK;

	// // map stack in the address space
	// paging::map::<BasePageSize>(
	// 	(new_addr - KERNEL_STACK_SIZE).try_into().unwrap(),
	// 	(new_addr - KERNEL_STACK_SIZE).try_into().unwrap(),
	// 	KERNEL_STACK_SIZE as usize / BasePageSize::SIZE,
	// 	PageTableEntryFlags::WRITABLE,
	// );

	loaderlog!("BootInfo located at 0x{:x}", &BOOT_INFO as *const _ as u64);
	// loaderlog!("Use stack address 0x{:x}", BOOT_INFO.current_stack_address);

	// let multiboot = Multiboot::new(mb_info as u64, paddr_to_slice).unwrap();
	// if let Some(cmdline) = multiboot.command_line() {
	// 	let address = cmdline.as_ptr();

	// 	// Identity-map the command line.
	// 	let page_address = align_down!(address as usize, BasePageSize::SIZE);
	// 	paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::empty());

	// 	//let cmdline = multiboot.command_line().unwrap();
	// 	BOOT_INFO.cmdline = address as u64;
	// 	BOOT_INFO.cmdsize = cmdline.len() as u64;
	// }

	// // Jump to the kernel entry point and provide the Multiboot information to it.
	//let entry_point = entry_point + address;
	loaderlog!(
		"Jumping to HermitCore Application Entry Point at 0x{:x}",
		entry_point
	);

	loaderlog!("BOOT_INFO: {:?}", BOOT_INFO);

	// asm!(
	// 	"mv tp, {thread_ptr}",
	// 	thread_ptr = in(reg) BOOT_INFO.tls_start,
	// );

	irq::install();

	let func: extern "C" fn(hart_id: usize, boot_info: &'static mut BootInfo) -> ! =
		core::mem::transmute(entry_point);

	func(INITIAL_HART_ID, &mut BOOT_INFO);

	//unreachable!();
}

// unsafe fn map_memory(address: usize, memory_size: usize) -> usize {
// 	let address = align_up!(address, LargePageSize::SIZE);
// 	let page_count = align_up!(memory_size, LargePageSize::SIZE) / LargePageSize::SIZE;

// 	paging::map::<LargePageSize>(address, address, page_count, PageTableEntryFlags::WRITABLE);

// 	address
// }

pub unsafe fn get_memory(memory_size: u64) -> u64 {
	physicalmem::allocate(align_up!(memory_size as usize, LargePageSize::SIZE)) as u64
}

#[no_mangle]
#[naked]
pub extern "C" fn _rust_start() -> ! {
	unsafe {
		asm!(
			// Initialize sp
			"sd a1, {dtb_ptr} ,t0",
			"sd a0, {hart_id} ,t0",
			"la	sp, __boot_core_stack_end_exclusive",
			//"li t0, {top_offset}",
			//"add sp, sp, t0",

			// jump to start
			"j loader_main",

			//boot_stack = sym BOOT_STACK,
			//top_offset = const KERNEL_STACK_SIZE - 16,
			dtb_ptr = sym DTB_PTR,
			hart_id = sym INITIAL_HART_ID,
			options(noreturn)
		)
	}
}

