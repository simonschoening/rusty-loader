// Copyright (c) 2018 Colin Finck, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use riscv::register::*;
use riscv::asm::wfi;
use trapframe::TrapFrame;

/// Init Interrupts
pub fn install() {
	unsafe{
		trapframe::init();
	}
}


/// Enable Interrupts
#[inline]
pub fn enable() {
	unsafe{
		sstatus::set_sie();
	}
}

/// Enable Interrupts and wait for the next interrupt (HLT instruction)
/// According to https://lists.freebsd.org/pipermail/freebsd-current/2004-June/029369.html, this exact sequence of assembly
/// instructions is guaranteed to be atomic.
/// This is important, because another CPU could call wakeup_core right when we decide to wait for the next interrupt.
#[inline]
pub fn enable_and_wait() {
	// TODO
	enable();
	unsafe{
		wfi();
	}
}

/// Disable Interrupts
#[inline]
pub fn disable() {
	unsafe { 
		sstatus::clear_sie()
	};
}

/// Disable IRQs (nested)
///
/// Disable IRQs when unsure if IRQs were enabled at all.
/// This function together with nested_enable can be used
/// in situations when interrupts shouldn't be activated if they
/// were not activated before calling this function.
#[inline]
pub fn nested_disable() -> bool {
	let  was_enabled = sstatus::read().sie();

	disable();
	was_enabled
}

/// Enable IRQs (nested)
///
/// Can be used in conjunction with nested_disable() to only enable
/// interrupts again if they were enabled before.
#[inline]
pub fn nested_enable(was_enabled: bool) {
	if was_enabled {
		enable();
	}
}

//Derived from rCore: https://github.com/rcore-os/rCore
/// Dispatch and handle interrupt.
///
/// This function is called from `trap.S` which is in the trapframe crate.
#[no_mangle]
pub extern "C" fn trap_handler(tf: &mut TrapFrame) {
    let scause = scause::read();
    let stval = stval::read();
    //trace!("Interrupt @ CPU{}: {:?} ", super::cpu::id(), scause.cause());
	loaderlog!("Interrupt: {:?} ", scause.cause());
    match scause.cause() {
        //Trap::Interrupt(I::SupervisorExternal) => external(),
        //Trap::Interrupt(I::SupervisorSoft) => ipi(),
        //Trap::Interrupt(I::SupervisorTimer) => crate::arch::riscv::kernel::scheduler::timer_handler(),
        //Trap::Exception(E::LoadPageFault) => page_fault(stval, tf),
        //Trap::Exception(E::StorePageFault) => page_fault(stval, tf),
        //Trap::Exception(E::InstructionPageFault) => page_fault(stval, tf),
        _ => panic!("unhandled trap {:?}, stval: {:x} tf {:#x?}", scause.cause(), stval, tf),
    }
}