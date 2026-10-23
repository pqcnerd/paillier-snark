//! Generated RISC Zero guest ELF and image ID.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

pub const PINNED_VEILGOV_BALLOT_GUEST_ID: [u32; 8] = [
    2804194256, 2447486412, 4238082596, 2715002596, 274625712, 1334816313, 677536285, 411457447,
];

const _: () = assert!(VEILGOV_BALLOT_GUEST_ID[0] == PINNED_VEILGOV_BALLOT_GUEST_ID[0]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_image_id_matches_pin() {
        assert_eq!(VEILGOV_BALLOT_GUEST_ID, PINNED_VEILGOV_BALLOT_GUEST_ID);
    }
}
