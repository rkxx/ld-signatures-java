package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

public abstract class BbsLdSigner<SIGNATURESUITE extends SignatureSuite> extends LdSigner<SIGNATURESUITE>{

    protected BbsLdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, Canonicalizer canonicalizer) {
        super(signatureSuite, signer, canonicalizer);
    }

    protected BbsLdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, Canonicalizer canonicalizer, URI creator, Date created, String domain, String challenge, String nonce, String proofPurpose, URI verificationMethod) {
        super(signatureSuite, signer, canonicalizer, creator, created, domain, challenge, nonce, proofPurpose, verificationMethod);
    }

    public abstract void sign(LdProof.Builder ldProofBuilder, List<byte[]> messages) throws GeneralSecurityException;

}
