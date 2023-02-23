package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.BBSPlus_PublicKeyVerifier;
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015BbsCanonicalizer;
import info.weboftrust.ldsignatures.suites.BbsBlsSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.util.List;

public class BbsBlsSignature2020LdVerifier extends BbsLdVerifier<BbsBlsSignature2020SignatureSuite> {

    public BbsBlsSignature2020LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATURE2020, verifier, new URDNA2015BbsCanonicalizer());
    }

    public BbsBlsSignature2020LdVerifier(byte[] publicKey) {

        this(new Bls12381G2_BBSPlus_PublicKeyVerifier(publicKey));
    }

    public BbsBlsSignature2020LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, BBSPlus_PublicKeyVerifier verifier) throws GeneralSecurityException {
        return verify(List.of(signingInput), ldProof, verifier);
    }

    public static boolean verify(List<byte[]> signingInput, LdProof ldProof, BBSPlus_PublicKeyVerifier verifier) throws GeneralSecurityException {

        // verify

        String proofValue = ldProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

        boolean verify;

        byte[] bytes = Multibase.decode(proofValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.BBSPlus);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, (BBSPlus_PublicKeyVerifier) this.getVerifier());
    }

    @Override
    public boolean verify(List<byte[]> messages, LdProof ldProof) throws GeneralSecurityException {

        return verify(messages, ldProof, (BBSPlus_PublicKeyVerifier) this.getVerifier());
    }
}
