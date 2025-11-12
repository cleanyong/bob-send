use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

const P_DEC: &str = "28766814515305344925135327846265618912664117797851731587904878015462803249977235941249703516789944091749898600299383135916258394165277154746850690924885409374613186677403293002561212823872134794612885736588353062665100257458192024578240831157340603512117881798371957928710301007355966949768954314381974229634562328230946414283068159460377595218094419073047560165707147374992696155554785175464279458669266476082782086850251603744388440411967541655962957589131628215119151589278605243618074656948031279999629258824412353704611067503482710930591891408577064246882098497237368756242458991599578221980723033002346183986743";
const Q_DEC: &str = "14383407257652672462567663923132809456332058898925865793952439007731401624988617970624851758394972045874949300149691567958129197082638577373425345462442704687306593338701646501280606411936067397306442868294176531332550128729096012289120415578670301756058940899185978964355150503677983474884477157190987114817281164115473207141534079730188797609047209536523780082853573687496348077777392587732139729334633238041391043425125801872194220205983770827981478794565814107559575794639302621809037328474015639999814629412206176852305533751741355465295945704288532123441049248618684378121229495799789110990361516501173091993371";
const G_DEC: &str = "4";

#[derive(Parser, Debug)]
#[command(
    name = "bob-send",
    about = "Bob responds to Alice's Diffie-Hellman public key, producing his own and the shared secret",
    disable_help_subcommand = true
)]
struct Args {
    /// Alice's public key A (decimal)
    #[arg(value_name = "ALICE_PUBLIC")]
    alice_public: String,

    /// Optional existing private key x_B. If omitted, a fresh key is generated.
    #[arg(long = "private", value_name = "DECIMAL")]
    private: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let params = DhParams::default();

    let alice_public = parse_decimal("alice_public", &args.alice_public)?;
    validate_public(&alice_public, &params)?;

    let private = match &args.private {
        Some(value) => parse_decimal("private", value)?,
        None => {
            let x = gen_privkey_uniform(&params.q);
            println!("Generated Bob private key (decimal):\n{}\n", x);
            x
        }
    };
    validate_private_in_range(&private, &params.q)?;

    let public = params.g.modpow(&private, &params.p);
    let shared = alice_public.modpow(&private, &params.p);

    println!("Bob private key (decimal):\n{}\n", private);
    println!("Bob private key (hex):\n0x{}\n", private.to_str_radix(16));
    println!("Bob public key (decimal):\n{}\n", public);
    println!("Bob public key (hex):\n0x{}\n", public.to_str_radix(16));
    println!("Shared secret (decimal):\n{}\n", shared);
    println!("Shared secret (hex):\n0x{}\n", shared.to_str_radix(16));
    println!("Send the Bob public key back to Alice so she can reproduce the same secret.");

    Ok(())
}

fn parse_decimal(label: &str, value: &str) -> Result<BigUint, String> {
    BigUint::parse_bytes(value.trim().as_bytes(), 10)
        .ok_or_else(|| format!("failed to parse {} as decimal BigUint", label))
}

fn validate_private_in_range(private: &BigUint, q: &BigUint) -> Result<(), String> {
    if private.is_zero() || private >= q {
        return Err(format!("private key must be in [1, q-1]; got {}", private));
    }
    Ok(())
}

fn validate_public(public: &BigUint, params: &DhParams) -> Result<(), String> {
    if public.is_zero() || public >= &params.p {
        return Err("public key must be in [1, p-1]".into());
    }
    if public.modpow(&params.q, &params.p) != BigUint::one() {
        return Err("public key is not in the expected subgroup".into());
    }
    Ok(())
}

fn gen_privkey_uniform(q: &BigUint) -> BigUint {
    assert!(q > &BigUint::one(), "q must be > 1");
    let mut rng = OsRng;
    loop {
        let candidate = rng.gen_biguint_below(q);
        if candidate.is_zero() {
            continue;
        }
        return candidate;
    }
}

struct DhParams {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

impl Default for DhParams {
    fn default() -> Self {
        Self {
            p: parse_decimal("p", P_DEC).expect("valid prime"),
            q: parse_decimal("q", Q_DEC).expect("valid q"),
            g: parse_decimal("g", G_DEC).expect("valid generator"),
        }
    }
}
