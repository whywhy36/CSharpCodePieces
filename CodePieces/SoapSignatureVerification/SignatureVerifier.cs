using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace CodePieces.SoapSignatureVerification
{
    class SignatureVerifier
    {
        public static bool CheckSignature(string fileName){
            // Load xml file
            var xmlDocument = new XmlDocument {PreserveWhitespace = true};
            xmlDocument.Load(fileName);

            // Define namespace manager for further usage
            var namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
            namespaceManager.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            // Retrieve binary security token and generate original certificate
            var input64BinarySecurityToken = xmlDocument.SelectSingleNode("//wsse:BinarySecurityToken", namespaceManager).InnerText;
            var certificate = new X509Certificate2(Convert.FromBase64String(input64BinarySecurityToken));

            var signedXml = new SignedXmlWithId(xmlDocument);

            // Retrieve original signature associated with the soap body
            var node = xmlDocument.SelectSingleNode("//ds:Signature", namespaceManager);
            signedXml.LoadXml((XmlElement)node);

            return signedXml.CheckSignature(certificate, true);
        }
    }

    // For this internal class, refer to http://stackoverflow.com/questions/5099156/malformed-reference-element-when-adding-a-reference-based-on-an-id-attribute-w
    class SignedXmlWithId : SignedXml
    {
        public SignedXmlWithId(XmlDocument xml) : base(xml)
        {
        }

        public SignedXmlWithId(XmlElement xmlElement) 
            : base(xmlElement)
        {       
        }

        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            // check to see if it's a standard ID reference
            XmlElement idElem = base.GetIdElement(doc, id);

            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
            }

            return idElem;
        }
    }
}
