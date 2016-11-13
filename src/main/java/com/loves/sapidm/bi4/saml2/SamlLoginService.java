/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.loves.sapidm.bi4.saml2;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCredentialResolverFactory;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;

import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 *
 * @author roney
 */
public class SamlLoginService extends HttpServlet {

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, SAXException, ParserConfigurationException, UnmarshallingException, TransformerException, ConfigurationException, XMLParserException {
        response.setContentType("text/html;charset=UTF-8");

        //Process SAML Response
        String responseMessage = request.getParameter("SAMLResponse");

        byte[] base64DecodedResponse = Base64.decode(responseMessage);

        //Unmarshalling reponse
        ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);

        DefaultBootstrap.bootstrap();
        
        BasicParserPool ppMgr = new BasicParserPool();
        
        ppMgr.setNamespaceAware(true);
	Document inCommonMDDoc = ppMgr.parse(is);
	Element rootElement = inCommonMDDoc.getDocumentElement();

        

        //Unmarshalling the element
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);
        XMLObject responseXmlObj = unmarshaller.unmarshall(rootElement);

        Response samlResponse = (Response) responseXmlObj;

        Assertion assertion = samlResponse.getAssertions().get(0);

        String subject = assertion.getSubject().getNameID().getValue();

        String issuer = assertion.getIssuer().getValue();

        String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();

        String statusCode = samlResponse.getStatus().getStatusCode().getValue();

        boolean validation = validateReponse(samlResponse,audience);

        if (validation) {
            request.setAttribute("subject", subject);
            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/BOE/custom.jsp");
            dispatcher.forward(request, response);
        } else {
            
        }
    }

    private boolean validateReponse(Response response,String audience) {

        try {
            Signature sig = response.getAssertions().get(0).getSignature();
            String catalinaHome = System.getProperty("catalina.home");
            //String catalinaHome = "/usr/local/Cellar/tomee-plus/1.7.4/libexec";
            

            Properties properties = new Properties();
            properties.load(new FileInputStream(catalinaHome + "/conf/saml2sp.props"));
            InputStream metaDataInputStream = new FileInputStream(properties.getProperty("metadata"));
            String intendedAudience = properties.getProperty("audience");
          

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            BasicParserPool pMgr = new BasicParserPool();
            Document metaDataDocument = pMgr.parse(metaDataInputStream);
            Element metadataRoot = metaDataDocument.getDocumentElement();
            metaDataInputStream.close();

            DOMMetadataProvider idpMetadataProvider = new DOMMetadataProvider(metadataRoot);
            idpMetadataProvider.setRequireValidMetadata(true);
            idpMetadataProvider.setParserPool(new BasicParserPool());
            idpMetadataProvider.initialize();

            MetadataCredentialResolverFactory credentialResolverFactory = MetadataCredentialResolverFactory.getFactory();

            MetadataCredentialResolver credentialResolver = credentialResolverFactory.getInstance(idpMetadataProvider);

            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
            criteriaSet.add(new EntityIDCriteria(properties.getProperty("entityid")));

            X509Credential credential = (X509Credential) credentialResolver.resolveSingle(criteriaSet);

            SignatureValidator validator = new SignatureValidator(credential);
            validator.validate(sig);
            
            if(intendedAudience.equalsIgnoreCase(audience)){
                return true;
            }
            else{
                return false;
            }

        } catch (Exception e) {
            return false;
        }
    }

    private void printElement(Document doc) throws TransformerException {

        DOMSource domSource = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);
        System.out.println(writer.toString());
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            processRequest(request, response);
        } catch (SAXException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnmarshallingException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (TransformerException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ConfigurationException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XMLParserException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            processRequest(request, response);
        } catch (SAXException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnmarshallingException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (TransformerException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ConfigurationException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XMLParserException ex) {
            Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
