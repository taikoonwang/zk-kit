const pad = (arr: any, len: number, val: any) => arr.concat(Array(len - arr.length).fill(val))
const pad0 = (arr: any, len: number) => pad(arr, len, BigInt(0))
const pad00 = (arr2D: any, h: number, w: number) => pad(arr2D, h, []).map((a: any) => pad0(a, w))

function checkParameter(value: any, name: string, ...types: string[]) {
    if (value === undefined) {
        throw new TypeError(`Parameter '${name}' is not defined`)
    }

    if (!types.includes(typeof value)) {
        throw new TypeError(`Parameter '${name}' is none of these types: ${types.join(", ")}`)
    }
}

export type HashTowerHashChainProof = {
    levelLengths: bigint
    digestOfDigests: bigint
    digests: bigint[]
    rootLv: number
    rootLevel: bigint[]
    childrens: bigint[][]
    item: bigint
}

/**
 * HashTowerHashChainProofBuilder is a TypeScript implementation of HashTower to generate proofs of membership.
 * @param H Height of tower of the proving circuit. It can be less than the H in the contract.
 * @param W Width of tower.
 * @param hash A hash function which supports 2 input values.
 */
export function HashTowerHashChainProofBuilder(H: number, W: number, hash: (a: bigint, b: bigint) => bigint) {
    checkParameter(H, "H", "number")
    checkParameter(W, "W", "number")
    checkParameter(hash, "hash", "function")

    const bitsPerLevel = 4
    const digestFunc = (arr: bigint[]) => arr.reduce(hash)
    const levels: bigint[][] = []
    const fullLevels: bigint[][] = []

    function _add(lv: number, toAdd: bigint) {
        if (lv === H) {
            throw new Error("The tower is full.")
        }

        if (lv === levels.length) {
            fullLevels.push([toAdd])
            levels.push([toAdd])
        } else if (levels[lv].length < W) {
            fullLevels[lv].push(toAdd)
            levels[lv].push(toAdd)
        } else {
            fullLevels[lv].push(toAdd)
            _add(lv + 1, digestFunc(levels[lv]))
            levels[lv] = [toAdd]
        }
    }
    /**
     * Adds a new item in the HashTower.
     * @param item Item to be added.
     */
    function add(item: bigint) {
        checkParameter(item, "item", "bigint")
        _add(0, item)
    }

    /**
     * Returns the index of a item. If the item does not exist it returns -1.
     * @param item Added item.
     * @returns Index of the item.
     */
    function indexOf(item: bigint) {
        checkParameter(item, "item", "bigint")
        return fullLevels[0].indexOf(item)
    }

    /**
     * Builds a proof of membership.
     * @param index Index of the proof's item.
     * @returns Proof object.
     */
    function build(idx: number): HashTowerHashChainProof {
        checkParameter(idx, "idx", "number")
        if (levels.length === 0) {
            throw new Error("The tower is empty.")
        }
        if (idx < 0 || idx >= fullLevels[0].length) {
            throw new Error(`Index out of range: ${idx}`)
        }

        const item = fullLevels[0][idx]
        let digests = levels.map(digestFunc)
        const digestOfDigests = digestFunc(digests.reverse())
        const levelLengths = levels.reduce(
            (sum, level, lv) => sum | (BigInt(level.length) << BigInt(bitsPerLevel * lv)),
            BigInt(0)
        )
        let childrens = []
        for (let lv = 0; ; lv += 1) {
            const levelStart = fullLevels[lv].length - levels[lv].length
            const start = idx - (idx % W)
            if (start === levelStart) {
                // we are in the tower now
                digests = pad0(digests, H)
                const rootLv = lv
                const rootLevel = pad0(fullLevels[lv].slice(start, start + levels[lv].length), W)
                childrens = pad00(childrens, H, W)
                return { levelLengths, digestOfDigests, digests, rootLv, rootLevel, childrens, item }
            }
            childrens.push(fullLevels[lv].slice(start, start + W))
            idx = Math.floor(idx / W)
        }
    }

    return { add, indexOf, build }
}
