import { derivePublicKey } from "@zk-kit/eddsa-poseidon"
import { Nonce, PlainText, poseidonDecrypt, poseidonEncrypt, poseidonPerm } from "@zk-kit/poseidon-cipher"
import { crypto } from "@zk-kit/utils"
import { WitnessTester } from "circomkit"
import { circomkit, genEcdhSharedKey } from "./common"

describe("poseidon-cipher", () => {
    let circuit: WitnessTester<["ciphertext", "nonce", "key"], ["decrypted"]>
    const privateKey = crypto.getRandomValues(32)
    const publicKey = derivePublicKey(privateKey)
    const encryptionKey = genEcdhSharedKey(privateKey, publicKey)
    const nonce: Nonce = BigInt(5)

    const setupCircuit = async (template: string, params: number[]) => {
        return await circomkit.WitnessTester("poseidon-cipher", {
            file: "poseidon-cipher",
            template,
            params
        })
    }

    describe("poseidonDecrypt", () => {
        it("Should correctly decrypt the ciphertext", async () => {
            const plainText: PlainText<bigint> = [BigInt(0), BigInt(1), BigInt(3)]
            const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)
            const decrypted = poseidonDecrypt(cipherText, encryptionKey, nonce, plainText.length)

            circuit = await setupCircuit("PoseidonDecrypt", [plainText.length])
            await circuit.expectPass({ ciphertext: cipherText, nonce, key: encryptionKey }, { decrypted })
        })

        it("Should correctly decrypt a ciphertext whose plaintext is not a multiple of 3", async () => {
            const plainText: PlainText<bigint> = [BigInt(0), BigInt(1), BigInt(3), BigInt(4)]
            const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)
            const decrypted = poseidonDecrypt(cipherText, encryptionKey, nonce, plainText.length)

            circuit = await setupCircuit("PoseidonDecrypt", [plainText.length])
            await circuit.expectPass({ ciphertext: cipherText, nonce, key: encryptionKey }, { decrypted })
        })

        it("Should throw when given an invalid input", async () => {
            const plainText: PlainText<bigint> = [BigInt(0), BigInt(1), BigInt(3), BigInt(0)]
            const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)
            cipherText[0] = BigInt(10001321)

            await circuit.expectFail({ ciphertext: cipherText, nonce, key: encryptionKey })
        })

        it("Should throw when trying to decrypt using a nonce >= 2^128", async () => {
            const plainText: PlainText<bigint> = [BigInt(0), BigInt(1), BigInt(3), BigInt(0)]
            const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)

            await circuit.expectFail({ ciphertext: cipherText, nonce: BigInt(2 ** 128 + 1), key: encryptionKey })
        })
    })

    describe("poseidonDecryptWithoutChecks", () => {
        const plainText: PlainText<bigint> = [BigInt(0), BigInt(1)]
        const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)
        const decrypted = poseidonDecrypt(cipherText, encryptionKey, nonce, plainText.length)

        before(async () => {
            circuit = await setupCircuit("PoseidonDecryptWithoutCheck", [plainText.length])
        })

        it("Should correctly decrypt the ciphertext", async () => {
            await circuit.expectPass({ ciphertext: cipherText, nonce, key: encryptionKey }, { decrypted })
        })

        it("Should not throw when given an invalid ciphertext", async () => {
            const invalid = { ciphertext: [...cipherText], nonce, key: encryptionKey }
            invalid.ciphertext[0] = BigInt(10001321)
            const witness = await circuit.calculateWitness(invalid)
            await circuit.expectConstraintPass(witness)
        })

        it("Should not throw when given an invalid nonce (< 2**128)", async () => {
            const invalid = { ciphertext: cipherText, nonce: BigInt(10001321), key: encryptionKey }
            const witness = await circuit.calculateWitness(invalid)
            await circuit.expectConstraintPass(witness)
        })

        it("Should not throw when given an invalid key", async () => {
            const invalid = { ciphertext: cipherText, nonce, key: [...encryptionKey] }
            invalid.key[0] = BigInt(10001321)
            const witness = await circuit.calculateWitness(invalid)
            await circuit.expectConstraintPass(witness)
        })
    })

    describe("poseidonIterations", () => {
        let circuit: WitnessTester<["ciphertext", "nonce", "key"], ["decrypted"]>

        const privateKey = crypto.getRandomValues(32)
        const publicKey = derivePublicKey(privateKey)
        const encryptionKey = genEcdhSharedKey(privateKey, publicKey)

        const plainText: PlainText<bigint> = [BigInt(0), BigInt(1)]
        const nonce: Nonce = BigInt(5)

        const cipherText = poseidonEncrypt(plainText, encryptionKey, nonce)
        const decrypted = poseidonDecrypt(cipherText, encryptionKey, nonce, plainText.length)

        const INPUT = {
            ciphertext: cipherText,
            nonce,
            key: encryptionKey
        }

        const OUTPUT = {
            decrypted
        }

        before(async () => {
            circuit = await circomkit.WitnessTester("poseidon-PoseidonDecryptIterations", {
                file: "poseidon-cipher",
                template: "PoseidonDecryptIterations",
                params: [plainText.length]
            })
        })

        it("Should correctly decrypt the ciphertext", async () => {
            await circuit.expectPass(INPUT, OUTPUT)
        })

        it("Should throw when given a nonce >= 2^128", async () => {
            const invalid = INPUT
            invalid.nonce = BigInt(2 ** 128 + 1)
            await circuit.expectFail(invalid)
        })
    })

    describe("poseidonPerm", () => {
        let circuit: WitnessTester<["inputs"], ["out"]>

        const inputs = [BigInt(0), BigInt(3)]
        const perms = poseidonPerm(inputs)

        const INPUT = {
            inputs
        }

        const OUTPUT = {
            out: perms
        }

        before(async () => {
            circuit = await circomkit.WitnessTester("poseidon-perm", {
                file: "poseidon-cipher",
                template: "PoseidonPerm",
                params: [inputs.length]
            })
        })

        it("Should compute the hash correctly", async () => {
            await circuit.expectPass(INPUT, OUTPUT)
        })
    })
})
