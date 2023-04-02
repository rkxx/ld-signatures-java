package info.weboftrust.ldsignatures.signer;

import bbs.signatures.ProofMessage;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.Proofer;
import com.danubetech.keyformats.crypto.impl.BBSPlus_Proofer;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class BbsLdSigner<SIGNATURESUITE extends SignatureSuite> extends LdSigner<SIGNATURESUITE>{

    private final BBSPlus_Proofer proofer;

    protected BbsLdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, BBSPlus_Proofer proofer, Canonicalizer canonicalizer) {
        super(signatureSuite, signer, canonicalizer, null, null, null, null, proofer != null ? Base64.getEncoder().encodeToString(proofer.getNonce()) : null, null, null);
        this.proofer = proofer;
    }

    protected BbsLdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, BBSPlus_Proofer proofer, Canonicalizer canonicalizer, URI creator, Date created, String domain, String challenge, String nonce, String proofPurpose, URI verificationMethod) {
        super(signatureSuite, signer, canonicalizer, creator, created, domain, challenge, nonce, proofPurpose, verificationMethod);
        this.proofer = proofer;
    }

    public void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException{
        sign(ldProofBuilder, List.of(signingInput));
    }

    public void sign(LdProof.Builder ldProofBuilder, List<byte[]> messages) throws GeneralSecurityException{
        throw new GeneralSecurityException("signing not supported by " + getSignatureSuite().getTerm());
    }

    public void deriveProof(LdProof.Builder ldProofBuilder, byte[] signature, List<ProofMessage> messages) throws GeneralSecurityException{
        throw new GeneralSecurityException("derive proof not supported by " + getSignatureSuite().getTerm());
    }

    public Proofer getProofer() {
        return this.proofer;
    }

}
