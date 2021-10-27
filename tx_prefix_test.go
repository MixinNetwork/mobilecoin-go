package api

import (
	"encoding/binary"
	"testing"

	"github.com/jadeydi/mobilecoin-account/block"
)

// Only for debug
func testDigestible(t *testing.T) {
	tx := &block.TxPrefix{
		Inputs: []*block.TxIn{
			&block.TxIn{
				Ring: []*block.TxOut{
					&block.TxOut{
						Amount: &block.Amount{
							Commitment: &block.CompressedRistretto{
								Data: []byte{76, 5, 35, 103, 155, 46, 70, 119, 136, 156, 15, 180, 114, 44, 205, 20, 117, 251, 62, 237, 97, 94, 82, 113, 221, 215, 148, 203, 36, 197, 129, 68},
							},
							MaskedValue: binary.LittleEndian.Uint64([]byte{189, 201, 155, 167, 120, 245, 99, 49}),
						},
						TargetKey: &block.CompressedRistretto{
							Data: []byte{156, 242, 192, 188, 213, 199, 213, 183, 158, 106, 153, 158, 115, 62, 211, 218, 232, 40, 87, 165, 222, 183, 185, 152, 12, 84, 101, 21, 110, 68, 14, 5},
						},
						PublicKey: &block.CompressedRistretto{
							Data: []byte{158, 0, 178, 214, 126, 114, 235, 188, 0, 208, 129, 29, 54, 72, 218, 102, 104, 7, 108, 83, 142, 182, 229, 91, 170, 203, 251, 150, 98, 254, 109, 105},
						},
						EFogHint: &block.EncryptedFogHint{
							Data: []byte{125, 252, 168, 236, 172, 12, 100, 86, 219, 243, 127, 143, 75, 235, 227, 25, 252, 250, 102, 84, 154, 83, 116, 145, 73, 225, 221, 156, 228, 183, 161, 244, 250, 173, 98, 144, 11, 1, 253, 228, 35, 84, 69, 168, 193, 100, 172, 113, 202, 101, 27, 16, 185, 27, 92, 188, 223, 228, 179, 2, 28, 214, 35, 74, 158, 78, 128, 228, 88, 140, 57, 114, 142, 163, 136, 30, 20, 58, 29, 205, 73, 157, 1, 0},
						},
					},
				},
				Proofs: []*block.TxOutMembershipProof{
					&block.TxOutMembershipProof{
						Index:        0,
						HighestIndex: 0,
					},
				},
			},
		},
		Outputs: []*block.TxOut{
			&block.TxOut{
				Amount: &block.Amount{
					Commitment: &block.CompressedRistretto{
						Data: []byte{40, 152, 32, 89, 243, 186, 130, 13, 41, 69, 188, 130, 53, 105, 218, 73, 185, 102, 56, 57, 12, 245, 65, 167, 228, 39, 22, 37, 223, 202, 156, 56},
					},
					MaskedValue: binary.LittleEndian.Uint64([]byte{223, 16, 160, 177, 241, 24, 70, 125}),
				},
				TargetKey: &block.CompressedRistretto{
					Data: []byte{178, 97, 194, 97, 253, 91, 130, 118, 12, 36, 205, 199, 165, 119, 67, 97, 138, 54, 0, 202, 86, 170, 167, 148, 24, 119, 160, 185, 206, 43, 211, 50},
				},
				PublicKey: &block.CompressedRistretto{
					Data: []byte{102, 12, 69, 64, 124, 12, 117, 79, 57, 142, 199, 248, 110, 61, 231, 237, 146, 82, 204, 57, 77, 225, 210, 233, 141, 133, 101, 238, 159, 177, 204, 83},
				},
				EFogHint: &block.EncryptedFogHint{
					Data: []byte{145, 30, 187, 44, 105, 120, 243, 69, 75, 0, 142, 22, 8, 211, 133, 43, 232, 127, 40, 160, 212, 120, 253, 102, 224, 76, 134, 212, 30, 98, 170, 81, 183, 250, 198, 11, 144, 94, 98, 68, 142, 255, 33, 102, 227, 153, 191, 90, 209, 255, 158, 247, 75, 185, 6, 183, 111, 97, 181, 203, 29, 113, 129, 50, 153, 83, 231, 14, 205, 173, 48, 104, 49, 4, 56, 209, 37, 101, 90, 183, 153, 230, 1, 0},
				},
			},
		},
		Fee:            binary.LittleEndian.Uint64([]byte{0, 228, 11, 84, 2, 0, 0, 0}),
		TombstoneBlock: binary.LittleEndian.Uint64([]byte{255, 255, 255, 255, 255, 255, 255, 255}),
	}

	_ = tx
	//log.Println(hex.EncodeToString(HashOfTxPrefix(tx)))
}
