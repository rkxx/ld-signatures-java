package info.weboftrust.ldsignatures.verifier;

import bbs.signatures.ProofMessage;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.ProofVerifier;
import com.danubetech.keyformats.crypto.Proofer;
import com.danubetech.keyformats.crypto.impl.BBSPlus_ProofVerifier;
import com.danubetech.keyformats.crypto.impl.BBSPlus_Proofer;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.security.GeneralSecurityException;
import java.util.List;

public class BbsLdVerifier<SIGNATURESUITE extends SignatureSuite> extends LdVerifier<SIGNATURESUITE> {

    private final BBSPlus_ProofVerifier proofVerifier;

    protected BbsLdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier, BBSPlus_ProofVerifier proofVerifier, Canonicalizer canonicalizer) {
        super(signatureSuite, verifier, canonicalizer);
        this.proofVerifier = proofVerifier;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {
        return verify(List.of(signingInput), ldProof);
    }

    public boolean verify(List<byte[]> messages, LdProof ldProof) throws GeneralSecurityException{
        throw new GeneralSecurityException("verifying not supported by " + getSignatureSuite().getTerm());
    }

    public boolean verifyProof(List<byte[]> messages, LdProof ldProof) throws GeneralSecurityException{
        throw new GeneralSecurityException("derive proof not supported by " + getSignatureSuite().getTerm());
    }

    public ProofVerifier getProofVerifier() {
        return this.proofVerifier;
    }

}
