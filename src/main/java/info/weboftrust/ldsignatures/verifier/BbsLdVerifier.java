package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.security.GeneralSecurityException;
import java.util.List;

public abstract class BbsLdVerifier<SIGNATURESUITE extends SignatureSuite> extends LdVerifier<SIGNATURESUITE> {

    protected BbsLdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier, Canonicalizer canonicalizer) {
        super(signatureSuite, verifier, canonicalizer);
    }

    public abstract boolean verify(List<byte[]> messages, LdProof ldProof) throws GeneralSecurityException;

}
