package info.weboftrust.ldsignatures.signer;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.BBSPlus_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.suites.BbsBlsSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.util.List;

public class BbsBlsSignature2020LdSigner extends BbsLdSigner<BbsBlsSignature2020SignatureSuite> {

    public BbsBlsSignature2020LdSigner(BBSPlus_PrivateKeySigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATURE2020, signer, new URDNA2015Canonicalizer());
    }

    public BbsBlsSignature2020LdSigner(KeyPair privateKey) {

        this(new Bls12381G2_BBSPlus_PrivateKeySigner(privateKey));
    }

    public BbsBlsSignature2020LdSigner() {

        this((BBSPlus_PrivateKeySigner) null);
    }

    public static void sign(LdProof.Builder ldProofBuilder, byte[] signingInput, BBSPlus_PrivateKeySigner signer) throws GeneralSecurityException {
        sign(ldProofBuilder, List.of(signingInput), signer);
    }


    public static void sign(LdProof.Builder ldProofBuilder, List<byte[]> messages, BBSPlus_PrivateKeySigner signer) throws GeneralSecurityException {

        // sign

        String proofValue;

        byte[] bytes = signer.sign(messages, JWSAlgorithm.BBSPlus);
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // add JSON-LD context

        ldProofBuilder.context(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, (BBSPlus_PrivateKeySigner) this.getSigner());
    }

    @Override
    public void sign(LdProof.Builder ldProofBuilder, List<byte[]> messages) throws GeneralSecurityException {

        sign(ldProofBuilder, messages, (BBSPlus_PrivateKeySigner) this.getSigner());
    }
}
