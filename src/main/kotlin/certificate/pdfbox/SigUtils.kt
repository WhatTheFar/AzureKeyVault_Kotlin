package certificate.pdfbox

/*
 * Copyright 2017 The Apache Software Foundation.
 *
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
 */

import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSBase
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature

/**
 * Utility class for the signature / timestamp examples.
 *
 * @author Tilman Hausherr
 */
object SigUtils {

    /**
     * Get the access permissions granted for this document in the DocMDP transform parameters
     * dictionary. Details are described in the table "Entries in the DocMDP transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters dictionary exists. Other
     * return values are 1, 2 or 3. 2 is also returned if the DocMDP transform parameters dictionary
     * is found but did not contain a /P entry, or if the value is outside the valid range.
     */
    fun getMDPPermission(doc: PDDocument): Int {
        var base = doc.documentCatalog.cosObject.getDictionaryObject(COSName.PERMS)
        if (base is COSDictionary) {
            base = base.getDictionaryObject(COSName.DOCMDP)
            if (base is COSDictionary) {
                base = base.getDictionaryObject("Reference")
                if (base is COSArray) {
                    val refArray = base
                    for (i in 0 until refArray.size()) {
                        base = refArray.getObject(i)
                        if (base is COSDictionary) {
                            val sigRefDict = base
                            if (COSName.DOCMDP == sigRefDict.getDictionaryObject("TransformMethod")) {
                                base = sigRefDict.getDictionaryObject("TransformParams")
                                if (base is COSDictionary) {
                                    var accessPermissions = base.getInt(COSName.P, 2)
                                    if (accessPermissions < 1 || accessPermissions > 3) {
                                        accessPermissions = 2
                                    }
                                    return accessPermissions
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0
    }

    /**
     * Set the access permissions granted for this document in the DocMDP transform parameters
     * dictionary. Details are described in the table "Entries in the DocMDP transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc The document.
     * @param signature The signature object.
     * @param accessPermissions The permission value (1, 2 or 3).
     */
    fun setMDPPermission(doc: PDDocument, signature: PDSignature, accessPermissions: Int) {
        val sigDict = signature.cosObject

        // DocMDP specific stuff
        val transformParameters = COSDictionary()
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"))
        transformParameters.setInt(COSName.P, accessPermissions)
        transformParameters.setName(COSName.V, "1.2")
        transformParameters.isNeedToBeUpdated = true

        val referenceDict = COSDictionary()
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"))
        referenceDict.setItem("TransformMethod", COSName.DOCMDP)
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"))
        referenceDict.setItem("TransformParams", transformParameters)
        referenceDict.isNeedToBeUpdated = true

        val referenceArray = COSArray()
        referenceArray.add(referenceDict)
        sigDict.setItem("Reference", referenceArray)
        referenceArray.isNeedToBeUpdated = true

        // Catalog
        val catalogDict = doc.documentCatalog.cosObject
        val permsDict = COSDictionary()
        catalogDict.setItem(COSName.PERMS, permsDict)
        permsDict.setItem(COSName.DOCMDP, signature)
        catalogDict.isNeedToBeUpdated = true
        permsDict.isNeedToBeUpdated = true
    }
}
