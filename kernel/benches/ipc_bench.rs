//! IPC fast-path + scheduler benchmarks (PLAN §6.5). Host-run via criterion;
//! measures the same engines the kernel links, minus arch context switching.
use criterion::{criterion_group, criterion_main, Criterion};
use ipc::Message;
use kernel::endpoint::{self, Envelope};
use kernel::sched::{self, ObjRef, ThreadId};

fn msg(label: u16, w0: u64) -> Message {
    let mut m = Message::new(label);
    m.words[0] = w0;
    m
}

fn bench_endpoint_roundtrip(c: &mut Criterion) {
    endpoint::reset_for_bench();
    sched::reset_for_bench();
    let _ = sched::init();
    let ep = endpoint::create_endpoint().unwrap();
    let sender = sched::spawn(ObjRef(1), 100).unwrap();
    let receiver = sched::spawn(ObjRef(1), 100).unwrap();

    c.bench_function("endpoint/try_send_mailbox", |b| {
        b.iter(|| {
            // Drain so each iteration starts with an empty mailbox.
            let _ = endpoint::try_recv(ep);
            endpoint::try_send(ep, Envelope::new(msg(0x0212, 42), sender)).unwrap();
        })
    });

    c.bench_function("endpoint/park_recv_wake_cycle", |b| {
        b.iter(|| {
            // Park the receiver, hand off, read the rendezvous slot.
            let _ = endpoint::recv(ep, receiver, false);
            endpoint::try_send(ep, Envelope::new(msg(0x0212, 7), sender)).unwrap();
            let _ = endpoint::take_delivered(receiver);
        })
    });
}

fn bench_sched(c: &mut Criterion) {
    sched::reset_for_bench();
    let _ = sched::init();
    let mut ids: [ThreadId; 8] = [ThreadId(0); 8];
    for (i, id) in ids.iter_mut().enumerate() {
        *id = sched::spawn(ObjRef(1), 100 - i as u8).unwrap();
    }
    c.bench_function("sched/yield_pick_8", |b| {
        b.iter(|| {
            for &t in &ids {
                let _ = sched::yield_now(t);
            }
            for _ in 0..8 {
                std::hint::black_box(sched::pick_next());
            }
        })
    });
}

fn bench_message_pack(c: &mut Criterion) {
    c.bench_function("ipc/message_pack_unpack", |b| {
        b.iter(|| {
            let mut m = Message::new(0x0213);
            m.tag = m.tag.with_caps(1);
            let _ = m.set_descriptor(0, ipc::CapSlot::pack(3, ipc::Rights::READ));
            std::hint::black_box(m.descriptor(0));
        })
    });
}

criterion_group!(
    benches,
    bench_endpoint_roundtrip,
    bench_sched,
    bench_message_pack
);
criterion_main!(benches);
