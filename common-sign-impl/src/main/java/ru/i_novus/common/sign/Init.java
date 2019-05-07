package ru.i_novus.common.sign;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost
 * -----------------------------------------------------------------
 * Copyright (C) 2018 - 2019 I-Novus LLC
 * -----------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------
 */

import lombok.SneakyThrows;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.transforms.Transform;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.i_novus.common.sign.api.GostIds;
import ru.i_novus.common.sign.smev.SmevTransformSpi;

import java.security.Security;

public final class Init {

    private static boolean initialized = false;

    private Init() {
    }

    @SneakyThrows
    public synchronized static void init() {
        if (initialized) {
            return;
        }
        org.apache.xml.security.Init.init();
        Security.removeProvider("ApacheXMLDSig");
        Security.addProvider(new XMLDSigRI());
        Security.addProvider(new BouncyCastleProvider());

        // GOST-3411
        JCEMapper.Algorithm digest = new JCEMapper.Algorithm("", "GOST3411", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_URI, digest);
        JCEMapper.register(GostIds.GOST3411_URN, digest);
        // GOST-3410-2001
        JCEMapper.Algorithm signature = new JCEMapper.Algorithm("", "GOST3411withECGOST3410", "Signature");
        JCEMapper.register(GostIds.GOST3410_2001_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2001_URN, signature);
        // GOST-3411-2012-256
        digest = new JCEMapper.Algorithm("", "GOST3411-2012-256", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_2012_256_URI, digest);
        JCEMapper.register(GostIds.GOST3411_2012_256_URN, digest);
        // GOST-3410-2012-256
        signature = new JCEMapper.Algorithm("", "GOST3411-2012-256withECGOST3410-2012-256", "Signature");
        JCEMapper.register(GostIds.GOST3410_2012_256_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2012_256_URN, signature);
        // GOST-3411-2012-512
        digest = new JCEMapper.Algorithm("", "GOST3411-2012-512", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_2012_512_URI, digest);
        JCEMapper.register(GostIds.GOST3411_2012_512_URN, digest);
        // GOST-3410-2012-512
        signature = new JCEMapper.Algorithm("", "GOST3411-2012-512withECGOST3410-2012-512", "Signature");
        JCEMapper.register(GostIds.GOST3410_2012_512_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2012_512_URN, signature);

        // GOST3410-2001
        SignatureAlgorithm.register(GostIds.GOST3410_2001_URI, SignatureGost.Gost3410_2001_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2001_URN, SignatureGost.Gost3410_2001_Urn.class);
        // GOST-3410-2012-256
        SignatureAlgorithm.register(GostIds.GOST3410_2012_256_URI, SignatureGost.Gost3410_2012_256_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2012_256_URN, SignatureGost.Gost3410_2012_256_Urn.class);
        // GOST-3410-2012-512
        SignatureAlgorithm.register(GostIds.GOST3410_2012_512_URI, SignatureGost.Gost3410_2012_512_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2012_512_URN, SignatureGost.Gost3410_2012_512_Urn.class);

        Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class);
        initialized = true;
    }
}
