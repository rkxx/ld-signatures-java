package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ProofVerifier;
import com.danubetech.keyformats.crypto.impl.BBSPlus_ProofVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015BbsCanonicalizer;
import info.weboftrust.ldsignatures.suites.BbsBlsSignatureProof2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;

public class BbsBlsSignatureProof2020LdVerifier extends BbsLdVerifier<BbsBlsSignatureProof2020SignatureSuite> {

    public BbsBlsSignatureProof2020LdVerifier(BBSPlus_ProofVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATUREPROOF2020, null, verifier, new URDNA2015BbsCanonicalizer());
    }

    public BbsBlsSignatureProof2020LdVerifier(byte[] publicKey) {

        this(new BBSPlus_ProofVerifier(publicKey));
    }

    public BbsBlsSignatureProof2020LdVerifier() {
        this((BBSPlus_ProofVerifier)null);
    }

    public static boolean verifyProof(List<byte[]> revealedMessages, LdProof ldProof, ProofVerifier proofVerifier) throws GeneralSecurityException {

        // verify

        String proofValue = ldProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

        String nonce = ldProof.getNonce();
        if (nonce == null) throw new GeneralSecurityException("No 'nonce' in proof.");

        boolean verify;

        byte[] proofValueBytes = Base64.getDecoder().decode(proofValue);
        byte[] nonceBytes = Base64.getDecoder().decode(nonce);
        verify = proofVerifier.verify(proofValueBytes, nonceBytes, revealedMessages, JWSAlgorithm.BBSPlus);

        // done

        return verify;
    }

    @Override
    public boolean verifyProof(List<byte[]> messages, LdProof ldProof) throws GeneralSecurityException {

        return verifyProof(messages, ldProof, this.getProofVerifier());
    }
}
