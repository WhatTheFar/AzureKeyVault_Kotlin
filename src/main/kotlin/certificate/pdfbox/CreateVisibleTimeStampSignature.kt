package certificate.pdfbox

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.io.IOUtils
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.PDResources
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.common.PDStream
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField
import org.apache.pdfbox.util.Hex
import org.apache.pdfbox.util.Matrix
import java.awt.Color
import java.awt.geom.AffineTransform
import java.awt.geom.Rectangle2D
import java.io.*
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.text.SimpleDateFormat
import java.util.*


/**
 * This is a second example for visual signing a pdf. It doesn't use the "design pattern" influenced
 * PDVisibleSignDesigner, and doesn't create its complex multilevel forms described in the Adobe
 * document
 * [Digital
 * Signature Appearances](https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/PPKAppearances.pdf), because this isn't required by the PDF specification. See the
 * discussion in December 2017 in PDFBOX-3198.
 *
 * @author Vakhtang Koroghlishvili
 * @author Tilman Hausherr
 */
class CreateVisibleTimeStampSignature
/**
 * Initialize the signature creator with a keystore (pkcs12) and pin that
 * should be used for the signature.
 *
 * @param keystore is a pkcs12 keystore.
 * @param pin is the pin for the keystore / private key
 * @throws KeyStoreException if the keystore has not been initialized (loaded)
 * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
 * @throws UnrecoverableKeyException if the given password is wrong
 * @throws CertificateException if the certificate is not valid as signing time
 * @throws IOException if no certificate could be found
 */
@Throws(KeyStoreException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, IOException::class, CertificateException::class)
constructor(keystore: KeyStore, pin: CharArray) : CreateSignatureBase(keystore, pin) {
    private var signatureOptions: SignatureOptions? = null
    /**
     * Set late external signing. Enable this if you want to activate the demo code where the
     * signature is kept and added in an extra step without using PDFBox methods. This is disabled
     * by default.
     *
     * @param lateExternalSigning
     */
    var isLateExternalSigning = false
    var imageFile: File? = null

    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @throws IOException
     */
    @Throws(IOException::class)
    fun signPDF(inputFile: File, signedFile: File, humanRect: Rectangle2D, tsaUrl: String) {
        this.signPDF(inputFile, signedFile, humanRect, tsaUrl, null)
    }

    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @param signatureFieldName optional name of an existing (unsigned) signature field
     * @throws IOException
     */
    @Throws(IOException::class)
    fun signPDF(inputFile: File?, signedFile: File, humanRect: Rectangle2D, tsaUrl: String?, signatureFieldName: String?) {
        if (inputFile == null || !inputFile.exists()) {
            throw IOException("Document for signing does not exist")
        }

        setTsaUrl(tsaUrl)

        // creating output document and prepare the IO streams.

        FileOutputStream(signedFile).use { fos ->
            PDDocument.load(inputFile).use { doc ->
                val accessPermissions = SigUtils.getMDPPermission(doc)
                if (accessPermissions == 1) {
                    throw IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary")
                }
                // Note that PDFBox has a bug that visual signing on certified files with permission 2
                // doesn't work properly, see PDFBOX-3699. As long as this issue is open, you may want to
                // be careful with such files.

                var signature: PDSignature? = null
                val acroForm = doc.documentCatalog.acroForm
                var rect: PDRectangle? = null

                // sign a PDF with an existing empty signature, as created by the CreateEmptySignatureForm example.
                if (acroForm != null) {
                    signature = findExistingSignature(acroForm, signatureFieldName)
                    if (signature != null) {
                        rect = acroForm.getField(signatureFieldName).widgets[0].rectangle
                    }
                }

                if (signature == null) {
                    // create signature dictionary
                    signature = PDSignature()
                }

                if (rect == null) {
                    rect = createSignatureRectangle(doc, humanRect)
                }

                // Optional: certify
                // can be done only if version is at least 1.5 and if not already set
                // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
                // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
                if (doc.version >= 1.5f && accessPermissions == 0) {
                    SigUtils.setMDPPermission(doc, signature, 2)
                }

                if (acroForm != null && acroForm.needAppearances) {
                    // PDFBOX-3738 NeedAppearances true results in visible signature becoming invisible
                    // with Adobe Reader
                    if (acroForm.fields.isEmpty()) {
                        // we can safely delete it if there are no fields
                        acroForm.cosObject.removeItem(COSName.NEED_APPEARANCES)
                        // note that if you've set MDP permissions, the removal of this item
                        // may result in Adobe Reader claiming that the document has been changed.
                        // and/or that field content won't be displayed properly.
                        // ==> decide what you prefer and adjust your code accordingly.
                    } else {
                        println("/NeedAppearances is set, signature may be ignored by Adobe Reader")
                    }
                }

                // default filter
                signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)

                // subfilter for basic and PAdES Part 2 signatures
                signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)

                signature.name = "Name"
                signature.location = "Location"
                signature.reason = "Reason"

                // the signing date, needed for valid signature
                signature.signDate = Calendar.getInstance()

                // do not set SignatureInterface instance, if external signing used
                val signatureInterface = if (isExternalSigning) null else this

                // register signature dictionary and sign interface
                signatureOptions = SignatureOptions()
                signatureOptions!!.setVisualSignature(createVisualSignatureTemplate(doc, 0, rect))
                signatureOptions!!.page = 0
                doc.addSignature(signature, signatureInterface, signatureOptions!!)

                if (isExternalSigning) {
                    println("Signing externally " + signedFile.name)
                    val externalSigning = doc.saveIncrementalForExternalSigning(fos)
                    // invoke external signature service
                    val cmsSignature = sign(externalSigning.content)

                    // Explanation of late external signing (off by default):
                    // If you want to add the signature in a separate step, then set an empty byte array
                    // and call signature.getByteRange() and remember the offset signature.getByteRange()[1]+1.
                    // you can write the ascii hex signature at a later time even if you don't have this
                    // PDDocument object anymore, with classic java file random access methods.
                    // If you can't remember the offset value from ByteRange because your context has changed,
                    // then open the file with PDFBox, find the field with findExistingSignature() or
                    // PODDocument.getLastSignatureDictionary() and get the ByteRange from there.
                    // Close the file and then write the signature as explained earlier in this comment.
                    if (isLateExternalSigning) {
                        // this saves the file with a 0 signature
                        externalSigning.setSignature(ByteArray(0))

                        // remember the offset (add 1 because of "<")
                        val offset = signature.byteRange[1] + 1

                        // now write the signature at the correct offset without any PDFBox methods
                        RandomAccessFile(signedFile, "rw").use { raf ->
                            raf.seek(offset.toLong())
                            raf.write(Hex.getBytes(cmsSignature))
                        }
                    } else {
                        // set signature bytes received from the service and save the file
                        externalSigning.setSignature(cmsSignature)
                    }
                } else {
                    // write incremental (only for signing purpose)
                    doc.saveIncremental(fos)
                }
            }
        }

        // Do not close signatureOptions before saving, because some COSStream objects within
        // are transferred to the signed document.
        // Do not allow signatureOptions get out of scope before saving, because then the COSDocument
        // in signature options might by closed by gc, which would close COSStream objects prematurely.
        // See https://issues.apache.org/jira/browse/PDFBOX-3743
        IOUtils.closeQuietly(signatureOptions)
    }

    private fun createSignatureRectangle(doc: PDDocument, humanRect: Rectangle2D): PDRectangle {
        val x = humanRect.x.toFloat()
        val y = humanRect.y.toFloat()
        val width = humanRect.width.toFloat()
        val height = humanRect.height.toFloat()
        val page = doc.getPage(0)
        val pageRect = page.cropBox
        val rect = PDRectangle()
        // signing should be at the same position regardless of page rotation.
        when (page.rotation) {
            90 -> {
                rect.lowerLeftY = x
                rect.upperRightY = x + width
                rect.lowerLeftX = y
                rect.upperRightX = y + height
            }
            180 -> {
                rect.upperRightX = pageRect.width - x
                rect.lowerLeftX = pageRect.width - x - width
                rect.lowerLeftY = y
                rect.upperRightY = y + height
            }
            270 -> {
                rect.lowerLeftY = pageRect.height - x - width
                rect.upperRightY = pageRect.height - x
                rect.lowerLeftX = pageRect.width - y - height
                rect.upperRightX = pageRect.width - y
            }
            0 -> {
                rect.lowerLeftX = x
                rect.upperRightX = x + width
                rect.lowerLeftY = pageRect.height - y - height
                rect.upperRightY = pageRect.height - y
            }
            else -> {
                rect.lowerLeftX = x
                rect.upperRightX = x + width
                rect.lowerLeftY = pageRect.height - y - height
                rect.upperRightY = pageRect.height - y
            }
        }
        return rect
    }

    // create a template PDF document with empty signature and return it as a stream.
    @Throws(IOException::class)
    private fun createVisualSignatureTemplate(srcDoc: PDDocument, pageNum: Int, rect: PDRectangle?): InputStream {
        PDDocument().use { doc ->
            val page = PDPage(srcDoc.getPage(pageNum).mediaBox)
            doc.addPage(page)
            val acroForm = PDAcroForm(doc)
            doc.documentCatalog.acroForm = acroForm
            val signatureField = PDSignatureField(acroForm)
            val widget = signatureField.widgets[0]
            val acroFormFields = acroForm.fields
            acroForm.isSignaturesExist = true
            acroForm.isAppendOnly = true
            acroForm.cosObject.isDirect = true
            acroFormFields.add(signatureField)

            widget.rectangle = rect!!

            // from PDVisualSigBuilder.createHolderForm()
            val stream = PDStream(doc)
            val form = PDFormXObject(stream)
            val res = PDResources()
            form.resources = res
            form.formType = 1
            val bbox = PDRectangle(rect.width, rect.height)
            var height = bbox.height
            var initialScale: Matrix? = null
            when (srcDoc.getPage(pageNum).rotation) {
                90 -> {
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1))
                    initialScale = Matrix.getScaleInstance(bbox.width / bbox.height, bbox.height / bbox.width)
                    height = bbox.width
                }
                180 -> form.setMatrix(AffineTransform.getQuadrantRotateInstance(2))
                270 -> {
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3))
                    initialScale = Matrix.getScaleInstance(bbox.width / bbox.height, bbox.height / bbox.width)
                    height = bbox.width
                }
                0 -> {
                }
                else -> {
                }
            }
            form.bBox = bbox
            val font = PDType1Font.HELVETICA_BOLD

            // from PDVisualSigBuilder.createAppearanceDictionary()
            val appearance = PDAppearanceDictionary()
            appearance.cosObject.isDirect = true
            val appearanceStream = PDAppearanceStream(form.cosObject)
            appearance.setNormalAppearance(appearanceStream)
            widget.appearance = appearance

            PDPageContentStream(doc, appearanceStream).use { cs ->
                // for 90Â° and 270Â° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null) {
                    cs.transform(initialScale)
                }

//                 show background (just for debugging, to see the rect size + position)
//                cs.setNonStrokingColor(Color.yellow)
//                cs.addRect(-5000f, -5000f, 10000f, 10000f)
//                cs.fill()


                // get TimeStamp
                val time = SimpleDateFormat("yyyy.MM.dd HH:mm:ss XXX").format(Date())

                // show text
                val fontSize = 10f
                val leading = fontSize * 1.5f
                cs.beginText()
                cs.setFont(font, fontSize)
                cs.setNonStrokingColor(Color.black)
                cs.newLineAtOffset(fontSize, height - leading)
                cs.setLeading(leading)
                cs.showText("Digitally signed by")
                cs.newLine()
                cs.showText(time)
                cs.endText()
            }

            // no need to set annotations and /P entry

            val baos = ByteArrayOutputStream()
            doc.save(baos)
            return ByteArrayInputStream(baos.toByteArray())
        }
    }

    // Find an existing signature (assumed to be empty). You will usually not need this.
    private fun findExistingSignature(acroForm: PDAcroForm?, sigFieldName: String?): PDSignature? {
        var signature: PDSignature? = null
        val signatureField: PDSignatureField?
        if (acroForm != null) {
            signatureField = acroForm.getField(sigFieldName) as PDSignatureField
            if (signatureField != null) {
                // retrieve signature dictionary
                signature = signatureField.signature
                if (signature == null) {
                    signature = PDSignature()
                    // after solving PDFBOX-3524
                    // signatureField.setValue(signature)
                    // until then:
                    signatureField.cosObject.setItem(COSName.V, signature)
                } else {
                    throw IllegalStateException("The signature field $sigFieldName is already signed.")
                }
            }
        }
        return signature
    }

    companion object {

        /**
         * Arguments are
         * [0] key store
         * [1] pin
         * [2] document that will be signed
         * [3] image of visible signature
         *
         * @param args
         * @throws java.security.KeyStoreException
         * @throws java.security.cert.CertificateException
         * @throws java.io.IOException
         * @throws java.security.NoSuchAlgorithmException
         * @throws java.security.UnrecoverableKeyException
         */
        @Throws(KeyStoreException::class, CertificateException::class, IOException::class, NoSuchAlgorithmException::class, UnrecoverableKeyException::class)
        @JvmStatic
        fun main(args: Array<String>) {
            // generate with
            // keytool -storepass 123456 -storetype PKCS12 -keystore file.p12 -genkey -alias client -keyalg RSA
            if (args.size < 4) {
                usage()
                System.exit(1)
            }

            var tsaUrl: String? = null
            // External signing is needed if you are using an external signing service, e.g. to sign
            // several files at once.
            var externalSig = false
            var i = 0
            while (i < args.size) {
                if ("-tsa" == args[i]) {
                    i++
                    if (i >= args.size) {
                        usage()
                        System.exit(1)
                    }
                    tsaUrl = args[i]
                }
                if ("-e" == args[i]) {
                    externalSig = true
                }
                i++
            }

            val ksFile = File(args[0])
            val keystore = KeyStore.getInstance("PKCS12")
            val pin = args[1].toCharArray()
            keystore.load(FileInputStream(ksFile), pin)

            val documentFile = File(args[2])

            val signing = CreateVisibleSignature2(keystore, pin.clone())

            signing.imageFile = File(args[3])

            val signedDocumentFile: File
            val name = documentFile.name
            val substring = name.substring(0, name.lastIndexOf('.'))
            signedDocumentFile = File(documentFile.parent, substring + "_signed.pdf")

            signing.isExternalSigning = externalSig

            // Set the signature rectangle
            // Although PDF coordinates start from the bottom, humans start from the top.
            // So a human would want to position a signature (x,y) units from the
            // top left of the displayed page, and the field has a horizontal width and a vertical height
            // regardless of page rotation.
            val humanRect = Rectangle2D.Float(100f, 200f, 150f, 50f)

            signing.signPDF(documentFile, signedDocumentFile, humanRect, tsaUrl, "Signature1")
        }

        /**
         * This will print the usage for this program.
         */
        private fun usage() {
            System.err.println("Usage: java " + CreateVisibleTimeStampSignature::class.java.name
                    + " <pkcs12-keystore-file> <pin> <input-pdf> <sign-image>\n" + "" +
                    "options:\n" +
                    "  -tsa <url>    sign timestamp using the given TSA server\n" +
                    "  -e            sign using external signature creation scenario")
        }
    }

}
