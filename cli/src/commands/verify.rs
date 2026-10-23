use anyhow::Result;
use std::fs;
use veilgov_tally::TallyResult;

pub fn run(path: &str) -> Result<()> {
    let data = fs::read_to_string(path)?;
    let result: TallyResult = serde_json::from_str(&data)?;
    println!("yes={}", result.yes);
    println!("no={}", result.no);
    println!("total={}", result.total);
    println!("ballot_count={}", result.ballot_count);
    println!("ballot_root={}", hex::encode(result.ballot_root));
    if result.development_only {
        println!("{}", result.warning);
    }
    if result.yes + result.no != result.total {
        anyhow::bail!("inconsistent yes+no != total");
    }
    println!("verify_result=ok");
    Ok(())
}
