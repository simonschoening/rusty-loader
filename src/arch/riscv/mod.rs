pub mod addr;
pub mod bootinfo;
pub mod irq;
pub mod paging;
pub mod physicalmem;
pub mod serial;
pub mod stack;

pub use self::bootinfo::*;
use crate::arch::paging::*;
use crate::arch::riscv::serial::SerialPort;
use crate::arch::stack::BOOT_STACK;
use core::arch::{asm, global_asm};
use core::{slice, str};
use goblin::elf;
use hermit_dtb::Dtb;

global_asm!(include_str!("head.S"));

// extern "C" {
// 	static kernel_end: u8;
// }

// CONSTANTS
pub const ELF_ARCH: u16 = elf::header::EM_RISCV;

pub const KERNEL_STACK_SIZE: usize = 32_768;
// const SERIAL_PORT_ADDRESS: u16 = 0x3F8;
// const SERIAL_PORT_BAUDRATE: u32 = 115200;

// VARIABLES
static COM1: SerialPort = SerialPort::new();
pub static mut BOOT_INFO: BootInfo = BootInfo::new();
static mut DTB_PTR: usize = 0x82200000;
static mut DTB_LENGTH: usize = 0;
static mut INITIAL_HART_ID: usize = usize::MAX;
static mut MEM_SIZE: u64 = 0;
static mut MEM_BASE: u64 = 0;
static mut TIMEBASE_FREQ: u64 = 0;
static mut INITRD_START: u64 = 0;
static mut INITRD_END: u64 = 0;

static mut CMDLINE: u64 = 0;
static mut CMDSIZE: u64 = 0;

//Each set bit indicates an available hart
static mut HART_MASK: u64 = 0;

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
	DTB_LENGTH = dtb.get_length();
	loaderlog!("DTB length: {}", DTB_LENGTH);

	let memory_reg = dtb
		.get_property("memory", "reg")
		.expect("Memory node not found in dtb");
	let timebase_data = dtb
		.get_property("cpus", "timebase-frequency")
		.expect("timebase-frequency node not found in /cpus");
	let initrd_start = dtb
		.get_property("chosen", "linux,initrd-start")
		.expect("linux,initrd-start node not found in /chosen");
	let initrd_end = dtb
		.get_property("chosen", "linux,initrd-end")
		.expect("linux,initrd-end node not found in /chosen");

	if let Some(cmdline) = dtb.get_property("chosen", "bootargs") {
		CMDSIZE = cmdline.len() as u64;
		CMDLINE = cmdline.as_ptr() as u64;
	}

	for i in (memory_reg.len() / 2)..(memory_reg.len()) {
		MEM_SIZE <<= 8;
		MEM_SIZE += memory_reg[i] as u64;
	}

	for i in 0..(memory_reg.len() / 2) {
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

	// loaderlog!("mem_base: {:x}, mem_size: {:x}, timebase-freq: {}", MEM_BASE, MEM_SIZE, TIMEBASE_FREQ);

	loaderlog!("Found initrd: [0x{:x} - 0x{:x}]", INITRD_START, INITRD_END);

	for node in dtb.enum_subnodes("cpus") {
		let path = &["cpus/", node].concat();
		let device_type_option = dtb.get_property(path, "device_type");
		if let Some(device_type) = device_type_option {
			if let Ok(string) = str::from_utf8(device_type) {
				if string == "cpu\u{0}" {
					let status_option = dtb.get_property(path, "status");
					let status = if let Some(status) = status_option {
						if let Ok(string) = str::from_utf8(status) {
							string
						} else {
							panic!("Invalid status in cpus/{:?}", node);
						}
					} else {
						"unknown"
					};

					let hart_id_slices = dtb
						.get_property(path, "reg")
						.expect("Missing hart_id in DTB");

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

	slice::from_raw_parts(
		INITRD_START as *const u8,
		(INITRD_END - INITRD_START) as usize,
	)
}

pub unsafe fn boot_kernel(
	_elf_address: Option<u64>,
	address: u64, // Physical address
	mem_size: u64,
	entry_point: u64,
) -> ! {
	// Supply the parameters to the HermitCore application.
	BOOT_INFO.base = address;
	BOOT_INFO.image_size = mem_size;
	BOOT_INFO.current_stack_address = &BOOT_STACK as *const _ as u64;

	BOOT_INFO.ram_start = MEM_BASE;
	BOOT_INFO.limit = MEM_SIZE;
	BOOT_INFO.timebase_freq = TIMEBASE_FREQ;
	BOOT_INFO.dtb_ptr = DTB_PTR as u64;
	BOOT_INFO.hart_mask = HART_MASK;

	BOOT_INFO.cmdline = CMDLINE;
	BOOT_INFO.cmdsize = CMDSIZE;

	loaderlog!("BootInfo located at 0x{:x}", &BOOT_INFO as *const _ as u64);
	loaderlog!("Use stack address 0x{:x}", BOOT_INFO.current_stack_address);

	//Jump to the kernel entry point
	loaderlog!(
		"Jumping to HermitCore Application Entry Point at 0x{:x}",
		entry_point
	);

	loaderlog!("BOOT_INFO: {:?}", BOOT_INFO);

	irq::install();

	let func: extern "C" fn(hart_id: usize, boot_info: &'static mut BootInfo) -> ! =
		core::mem::transmute(entry_point);

	func(INITIAL_HART_ID, &mut BOOT_INFO);
}

pub unsafe fn get_memory(memory_size: u64) -> u64 {
	// TODO: Fix this

	let mut start_address;
	if DTB_PTR < INITRD_START as usize {
		loaderlog!("DTB is located before application");
		start_address = align_up!(DTB_PTR + DTB_LENGTH as usize, LargePageSize::SIZE);
		if start_address + memory_size as usize >= INITRD_START as usize {
			start_address = align_up!(INITRD_END as usize, LargePageSize::SIZE);
			loaderlog!("Loading kernel after initrd");
		} else {
			loaderlog!("Loading kernel before initrd");
		}
	} else {
		loaderlog!("DTB is located after application");
		start_address = align_up!(INITRD_END as usize, LargePageSize::SIZE);
		if start_address + memory_size as usize >= DTB_PTR {
			start_address = align_up!(DTB_PTR + DTB_LENGTH as usize, LargePageSize::SIZE);
			loaderlog!("Loading kernel after dtb");
		} else {
			loaderlog!("Loading kernel before dtb");
		}
	}

	physicalmem::init(start_address);
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

			// jump to start
			"j loader_main",

			dtb_ptr = sym DTB_PTR,
			hart_id = sym INITIAL_HART_ID,
			options(noreturn)
		)
	}
}
