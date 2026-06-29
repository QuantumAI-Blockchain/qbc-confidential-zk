// Empirical witness-indistinguishability on the PLONKY3 transfer proofs (native FRI ZK).
// Generates proofs differing only in a hidden amount and trains a held-out linear distinguisher.
// ZK => accuracy ~ 0.5. Positive control (injected signal) => ~1.0.
use qbc_pq_confidential_p3::transfer::prove_transfer;

fn rng() -> u64 { let mut b=[0u8;8]; getrandom::fill(&mut b).unwrap(); u64::from_le_bytes(b) & ((1u64<<40)-1) }

// balanced 2-in/2-out, out0 = a, fresh blindings. inputs sum 15, fee 0.
fn proof_amt(a: u64) -> Vec<u8> {
    let ins=[(10u64,rng()),(5u64,rng())];
    let outs=[(a,rng()),(15-a,rng())];
    prove_transfer(&ins,&outs,0).expect("ok").2
}
fn centroid(s:&[Vec<f64>])->Vec<f64>{let n=s.len() as f64;let d=s[0].len();let mut c=vec![0f64;d];for x in s{for i in 0..d{c[i]+=x[i];}}for v in c.iter_mut(){*v/=n;}c}
fn dot(a:&[f64],b:&[f64])->f64{a.iter().zip(b).map(|(x,y)|x*y).sum()}
fn linacc(a:&[Vec<f64>],b:&[Vec<f64>],tr:usize)->f64{
    let ca=centroid(&a[..tr]); let cb=centroid(&b[..tr]);
    let w:Vec<f64>=ca.iter().zip(&cb).map(|(x,y)|x-y).collect();
    let p=|s:&Vec<f64>|dot(s,&w);
    let ma:f64=a[..tr].iter().map(p).sum::<f64>()/tr as f64;
    let mb:f64=b[..tr].iter().map(p).sum::<f64>()/tr as f64;
    let thr=(ma+mb)/2.0; let ahi=ma>=mb;
    let mut ok=0usize; let mut n=0usize;
    for s in &a[tr..]{ if (p(s)>=thr)==ahi {ok+=1;} n+=1; }
    for s in &b[tr..]{ if (p(s)>=thr)!=ahi {ok+=1;} n+=1; }
    ok as f64/n as f64
}

#[test]
fn p3_transfer_zk_no_amount_leak() {
    let per = std::env::var("P3_PER").ok().and_then(|s|s.parse().ok()).unwrap_or(120usize);
    let tr=(per*7)/10;
    let a:Vec<Vec<u8>>=(0..per).map(|_|proof_amt(3)).collect();
    let b:Vec<Vec<u8>>=(0..per).map(|_|proof_amt(12)).collect();
    let plen=a.iter().chain(&b).map(|p|p.len()).min().unwrap();
    let to_f=|p:&Vec<u8>|->Vec<f64>{p[..plen].iter().map(|&x|x as f64).collect()};
    let af:Vec<_>=a.iter().map(to_f).collect();
    let bf:Vec<_>=b.iter().map(to_f).collect();
    let acc=linacc(&af,&bf,tr);
    // positive control
    let mut al=af.clone(); let mut bl=bf.clone();
    for s in al.iter_mut(){s.push(3000.0);} for s in bl.iter_mut(){s.push(12000.0);}
    let pc=linacc(&al,&bl,tr);
    println!("P3 LEAKAGE: per_class={per} proof_len={plen} distinguisher_acc={acc:.4} positive_control={pc:.4}");
    assert!((acc-0.5).abs()<0.15, "p3 amount distinguisher should be ~chance, got {acc}");
    assert!(pc>0.9, "positive control should separate");
    // randomization
    let p1=proof_amt(6); let p2=proof_amt(6);
    assert_ne!(p1,p2,"two p3 proofs must differ (ZK)");
}
