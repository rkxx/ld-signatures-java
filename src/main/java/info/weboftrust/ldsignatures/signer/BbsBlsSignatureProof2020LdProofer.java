package info.weboftrust.ldsignatures.signer;

import bbs.signatures.ProofMessage;
import com.danubetech.keyformats.crypto.Proofer;
import com.danubetech.keyformats.crypto.impl.BBSPlus_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.BBSPlus_Proofer;
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_Proofer;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015BbsCanonicalizer;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.suites.BbsBlsSignatureProof2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import org.apache.commons.codec.binary.Hex;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;

public class BbsBlsSignatureProof2020LdProofer extends BbsLdSigner<BbsBlsSignatureProof2020SignatureSuite> {

    public BbsBlsSignatureProof2020LdProofer(BBSPlus_Proofer proofer) {
        super(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATUREPROOF2020, null, proofer, new URDNA2015BbsCanonicalizer());
    }

    public BbsBlsSignatureProof2020LdProofer(byte[] publicKey, byte[] nonce) {
        this(new Bls12381G2_BBSPlus_Proofer(publicKey, nonce));
    }

    public BbsBlsSignatureProof2020LdProofer() {
        this(null);
    }

    public static void deriveProof(LdProof.Builder ldProofBuilder, byte[] signature, List<ProofMessage> messages, Proofer proofer) throws GeneralSecurityException {

        // sign

        String proofValue;

        byte[] bytes = proofer.deriveProof(signature, messages, JWSAlgorithm.BBSPlus);
        proofValue = new String(Base64.getEncoder().encode(bytes));

        // add JSON-LD context

        ldProofBuilder.context(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void deriveProof(LdProof.Builder ldProofBuilder, byte[] signature, List<ProofMessage> messages) throws GeneralSecurityException {
        deriveProof(ldProofBuilder, signature, messages, this.getProofer());
    }
}
