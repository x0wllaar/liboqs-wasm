let primitives = null;

const OQS_SUCCESS = 0;
const size_t_len = 4;

const CreateLibOQSPrimitives = async () => {
    const mod = await CreateLibOQS();

    return {
        //Memory
        malloc: mod.cwrap('malloc', 'number', ['number']),
        free: mod.cwrap('free', 'void', ['number']),
        OQS_MEM_secure_free: mod.cwrap('OQS_MEM_secure_free', 'void', ['number', 'number']),
        OQS_MEM_insecure_free: mod.cwrap('OQS_MEM_insecure_free', 'void', ['number']),

        //KEMs
        OQS_KEM_new: mod.cwrap('OQS_KEM_new', 'number', ['string']),
        OQS_KEM_free: mod.cwrap('OQS_KEM_free', 'void', ['number']),
        OQS_KEM_keypair: mod.cwrap('OQS_KEM_keypair', 'number', ['number', 'number', 'number']),
        OQS_KEM_encaps: mod.cwrap('OQS_KEM_encaps', 'number', ['number', 'number', 'number', 'number']),
        OQS_KEM_decaps: mod.cwrap('OQS_KEM_decaps', 'number', ['number', 'number', 'number', 'number']),

        //KEM Accessors
        OQS_KEM_get_method_name: mod.cwrap('OQS_KEM_get_method_name', 'string', ['number']),
        OQS_KEM_get_alg_version: mod.cwrap('OQS_KEM_get_alg_version', 'string', ['number']),
        OQS_KEM_get_ind_cca: mod.cwrap('OQS_KEM_get_ind_cca', 'number', ['number']),
        OQS_KEM_get_length_public_key: mod.cwrap('OQS_KEM_get_length_public_key', 'number', ['number']),
        OQS_KEM_get_length_secret_key: mod.cwrap('OQS_KEM_get_length_secret_key', 'number', ['number']),
        OQS_KEM_get_length_ciphertext: mod.cwrap('OQS_KEM_get_length_ciphertext', 'number', ['number']),
        OQS_KEM_get_length_shared_secret: mod.cwrap('OQS_KEM_get_length_shared_secret', 'number', ['number']),

        //SIGs
        OQS_SIG_new: mod.cwrap('OQS_SIG_new', 'number', ['string']),
        OQS_SIG_free: mod.cwrap('OQS_SIG_free', 'void', ['number']),
        OQS_SIG_keypair: mod.cwrap('OQS_SIG_keypair', 'number', ['number', 'number', 'number']),
        OQS_SIG_sign: mod.cwrap('OQS_SIG_sign', 'number', ['number', 'number', 'number', 'number', 'number']),
        OQS_SIG_verify: mod.cwrap('OQS_SIG_verify', 'number', ['number', 'number', 'number', 'number', 'number']),

        //SIG Accessors
        OQS_SIG_get_method_name: mod.cwrap('OQS_SIG_get_method_name', 'string', ['number']),
        OQS_SIG_get_alg_version: mod.cwrap('OQS_SIG_get_alg_version', 'string', ['number']),
        OQS_SIG_get_euf_cma: mod.cwrap('OQS_SIG_get_euf_cma', 'number', ['number']),
        OQS_SIG_get_length_public_key: mod.cwrap('OQS_SIG_get_length_public_key', 'number', ['number']),
        OQS_SIG_get_length_secret_key: mod.cwrap('OQS_SIG_get_length_secret_key', 'number', ['number']),
        OQS_SIG_get_length_signature: mod.cwrap('OQS_SIG_get_length_signature', 'number', ['number']),

        //HEAP
        HEAPU8: mod.HEAPU8,
    }
};

const GetLibOQSPrimitives = async () => {
    if (primitives === null) {
        primitives = await CreateLibOQSPrimitives();
    }

    return primitives;
};

export class OQSKem {
    constructor(primitives, name) {
        this.primitives = primitives;
        this.name = name;

        const cKem = this.primitives.OQS_KEM_new(this.name)
        if (cKem === 0) {
            throw new Error('Failed to create KEM, not supported by liboqs');
        }
        
        //We interrogate the KEM to get the lengths of the keys and ciphertexts
        this.lenSK = this.primitives.OQS_KEM_get_length_secret_key(cKem);
        this.lenPK = this.primitives.OQS_KEM_get_length_public_key(cKem);
        this.lenCT = this.primitives.OQS_KEM_get_length_ciphertext(cKem);
        this.lenSS = this.primitives.OQS_KEM_get_length_shared_secret(cKem);

        this.primitives.OQS_KEM_free(cKem)
    }

    static async create(name) {
        const primitives = await GetLibOQSPrimitives();
        return new OQSKem(primitives, name);
    }

    //This is a helper function to allocate memory on the heap
    malloc(size) {
        const ptr = this.primitives.malloc(size);
        if (ptr === 0) {
            throw new Error('Failed to allocate memory');
        }
        return ptr;
    }

    //This is a helper function to allocate memory on the heap and schedule it to be zeroed out and freed
    secureMalloc(size, cleanupStack) {
        const ptr = this.malloc(size);
        cleanupStack.push(() => this.primitives.OQS_MEM_secure_free(ptr, size));
        return ptr;
    }

    //This is a helper function to allocate memory on the heap and schedule it to be freed
    newKemInstance(cleanupStack) {
        const kem = this.primitives.OQS_KEM_new(this.name);
        if (kem === 0) {
            throw new Error('Failed to create KEM, not supported by liboqs');
        }
        cleanupStack.push(() => this.primitives.OQS_KEM_free(kem));
        return kem;
    }

    keypair() {
        const cleanupStack = [];
        try {
            const kem = this.newKemInstance(cleanupStack);
            const publicKeyPtr = this.secureMalloc(this.lenPK, cleanupStack);
            const secretKeyPtr = this.secureMalloc(this.lenSK, cleanupStack);
            
            if (this.primitives.OQS_KEM_keypair(kem, publicKeyPtr, secretKeyPtr) !== OQS_SUCCESS) {
                throw new Error('Failed to generate keypair');
            }

            //The slice is to copy the data out of the heap
            //It will be zeroed out when the memory is freed by OQS_MEM_secure_free
            const publicKey = new Uint8Array(this.primitives.HEAPU8.buffer, publicKeyPtr, this.lenPK).slice(0);
            const secretKey = new Uint8Array(this.primitives.HEAPU8.buffer, secretKeyPtr, this.lenSK).slice(0);

            return { publicKey, secretKey };
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    encapsulate(publicKey) {
        const cleanupStack = [];
        try {
            const kem = this.newKemInstance(cleanupStack);

            const publicKeyPtr = this.malloc(this.lenPK);
            const ciphertextPtr = this.secureMalloc(this.lenCT, cleanupStack);
            const sharedSecretPtr = this.secureMalloc(this.lenSS, cleanupStack);

            this.primitives.HEAPU8.set(publicKey, publicKeyPtr);

            if (this.primitives.OQS_KEM_encaps(kem, ciphertextPtr, sharedSecretPtr, publicKeyPtr) !== OQS_SUCCESS) {
                throw new Error('Failed to encapsulate');
            }

            const ciphertext = new Uint8Array(this.primitives.HEAPU8.buffer, ciphertextPtr, this.lenCT).slice(0);
            const sharedSecret = new Uint8Array(this.primitives.HEAPU8.buffer, sharedSecretPtr, this.lenSS).slice(0);

            return { ciphertext, sharedSecret };

        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    decapsulate(ciphertext, secretKey) {
        const cleanupStack = [];
        try {
            const kem = this.newKemInstance(cleanupStack);

            const secretKeyPtr = this.secureMalloc(this.lenSK, cleanupStack);
            const ciphertextPtr = this.secureMalloc(this.lenCT, cleanupStack);
            const sharedSecretPtr = this.secureMalloc(this.lenSS, cleanupStack);

            this.primitives.HEAPU8.set(secretKey, secretKeyPtr);
            this.primitives.HEAPU8.set(ciphertext, ciphertextPtr);

            if (this.primitives.OQS_KEM_decaps(kem, sharedSecretPtr, ciphertextPtr, secretKeyPtr) !== OQS_SUCCESS) {
                throw new Error('Failed to encapsulate');
            }

            const sharedSecret = new Uint8Array(this.primitives.HEAPU8.buffer, sharedSecretPtr, this.lenSS).slice(0);
            return sharedSecret;

        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    isIndCca() {
        const cleanupStack = [];
        try{
            const kem = this.newKemInstance(cleanupStack);
            return this.primitives.OQS_KEM_get_ind_cca(kem) === 1;
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    getAlgVersion() {
        const cleanupStack = [];
        try{
            const kem = this.newKemInstance(cleanupStack);
            return this.primitives.OQS_KEM_get_alg_version(kem);
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    getMethodName() {
        const cleanupStack = [];
        try{
            const kem = this.newKemInstance(cleanupStack);
            return this.primitives.OQS_KEM_get_method_name(kem);
        } finally {
            cleanupStack.forEach(op => op());
        }
    }
}

export const VerificationError = new Error('Signature verification failed');

export class OQSSig {
    constructor(primitives, name) {
        this.primitives = primitives;
        this.name = name;

        const cSig = this.primitives.OQS_SIG_new(this.name)
        if (cSig === 0) {
            throw new Error('Failed to create SIG, not supported by liboqs');
        }
        
        //We interrogate the SIG to get the lengths of the keys and ciphertexts
        this.lenSK = this.primitives.OQS_SIG_get_length_secret_key(cSig);
        this.lenPK = this.primitives.OQS_SIG_get_length_public_key(cSig);
        this.lenSG = this.primitives.OQS_SIG_get_length_signature(cSig);

        this.primitives.OQS_SIG_free(cSig)
    }

    static async create(name) {
        const primitives = await GetLibOQSPrimitives();
        return new OQSSig(primitives, name);
    }

    //This is a helper function to allocate memory on the heap
    malloc(size) {
        const ptr = this.primitives.malloc(size);
        if (ptr === 0) {
            throw new Error('Failed to allocate memory');
        }
        return ptr;
    }

    //This is a helper function to allocate memory on the heap and schedule it to be zeroed out and freed
    secureMalloc(size, cleanupStack) {
        const ptr = this.malloc(size);
        cleanupStack.push(() => this.primitives.OQS_MEM_secure_free(ptr, size));
        return ptr;
    }

    //This is a helper function to allocate memory on the heap and schedule it to be freed
    newSigInstance(cleanupStack) {
        const sig = this.primitives.OQS_SIG_new(this.name);
        if (sig === 0) {
            throw new Error('Failed to create SIG, not supported by liboqs');
        }
        cleanupStack.push(() => this.primitives.OQS_SIG_free(sig));
        return sig;
    }

    keypair() {
        const cleanupStack = [];
        try {
            const sig = this.newSigInstance(cleanupStack);
            const publicKeyPtr = this.secureMalloc(this.lenPK, cleanupStack);
            const secretKeyPtr = this.secureMalloc(this.lenSK, cleanupStack);
            
            if (this.primitives.OQS_SIG_keypair(sig, publicKeyPtr, secretKeyPtr) !== OQS_SUCCESS) {
                throw new Error('Failed to generate keypair');
            }

            //The slice is to copy the data out of the heap
            //It will be zeroed out when the memory is freed by OQS_MEM_secure_free
            const publicKey = new Uint8Array(this.primitives.HEAPU8.buffer, publicKeyPtr, this.lenPK).slice(0);
            const secretKey = new Uint8Array(this.primitives.HEAPU8.buffer, secretKeyPtr, this.lenSK).slice(0);

            return { publicKey, secretKey };
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    sign(message, secretKey) {
        const cleanupStack = [];
        try {
            const sig = this.newSigInstance(cleanupStack);

            const secretKeyPtr = this.secureMalloc(this.lenSK, cleanupStack);
            const messagePtr = this.secureMalloc(message.length, cleanupStack);
            const signaturePtr = this.secureMalloc(this.lenSG, cleanupStack);
            const sigLenPtr = this.secureMalloc(size_t_len, cleanupStack);

            this.primitives.HEAPU8.set(secretKey, secretKeyPtr);
            this.primitives.HEAPU8.set(message, messagePtr);

            if (this.primitives.OQS_SIG_sign(sig, signaturePtr, sigLenPtr, messagePtr, message.length, secretKeyPtr) !== OQS_SUCCESS) {
                throw new Error('Failed to sign');
            }

            const sigLenBytes = new Uint8Array(this.primitives.HEAPU8.buffer, sigLenPtr, size_t_len).slice(0);
            const sigLen = new DataView(sigLenBytes.buffer).getUint32(0, true);

            const signature = new Uint8Array(this.primitives.HEAPU8.buffer, signaturePtr, sigLen).slice(0);

            return signature;

        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    verify(message, signature, publicKey) {
        const cleanupStack = [];
        try {
            const sig = this.newSigInstance(cleanupStack);

            const publicKeyPtr = this.secureMalloc(this.lenPK, cleanupStack);
            const messagePtr = this.secureMalloc(message.length, cleanupStack);
            const signaturePtr = this.secureMalloc(signature.length, cleanupStack);

            this.primitives.HEAPU8.set(publicKey, publicKeyPtr);
            this.primitives.HEAPU8.set(message, messagePtr);
            this.primitives.HEAPU8.set(signature, signaturePtr);

            const res = this.primitives.OQS_SIG_verify(sig, messagePtr, message.length, signaturePtr, signature.length, publicKeyPtr);
            if (res !== OQS_SUCCESS) {
                throw VerificationError;
            }
            return true;

        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    isEufCma() {
        const cleanupStack = [];
        try{
            const sig = this.newSigInstance(cleanupStack);
            return this.primitives.OQS_SIG_get_euf_cma(sig) === 1;
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    getAlgVersion() {
        const cleanupStack = [];
        try{
            const sig = this.newSigInstance(cleanupStack);
            return this.primitives.OQS_SIG_get_alg_version(sig);
        } finally {
            cleanupStack.forEach(op => op());
        }
    }

    getMethodName() {
        const cleanupStack = [];
        try{
            const sig = this.newSigInstance(cleanupStack);
            return this.primitives.OQS_SIG_get_method_name(sig);
        } finally {
            cleanupStack.forEach(op => op());
        }
    }
}