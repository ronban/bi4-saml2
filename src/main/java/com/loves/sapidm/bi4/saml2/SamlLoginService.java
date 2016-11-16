/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.loves.sapidm.bi4.saml2;

import java.io.*;
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
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
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
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;

import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
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


    private String intendedAudience;
    private X509Credential credential;
    private Properties configuration;

    private String samlSubject;
    private String samlIssuer;
    private String samlStatusCode;
    private String samlAudience;


    //Constants
    private final String AUDIENCE_TAG = "audience";
    private final String METADATA_TAG = "metadata";
    private final String ENTITYID_TAG = "entityid";
    private final String FORWARDED_URL_TAG = "forwardurl";
    private final String USERNAME_ATTR_TAG = "userattr";

    private final String CONF_LOCATION = "/conf/saml2sp.props";


    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, SAXException, ParserConfigurationException, UnmarshallingException, TransformerException, ConfigurationException, XMLParserException, ValidationException {
        response.setContentType("text/html;charset=UTF-8");

        //Get SAML Response from request
        String responseMessage = request.getParameter("SAMLResponse");

        //Process SAML Response
        Response samlResponse = processSamlLogin(responseMessage);

        //Validate SAML Response
        if(validateReponse(samlResponse)){
            //forward to the configured URL with the configured
            System.out.println(configuration.getProperty(FORWARDED_URL_TAG) + "?" + configuration.getProperty(USERNAME_ATTR_TAG) + "=" + this.samlSubject);
            response.sendRedirect(configuration.getProperty(FORWARDED_URL_TAG) + "?" + configuration.getProperty(USERNAME_ATTR_TAG) + "=" + this.samlSubject);
        }
        else{
            //return ERROR
            throw new ValidationException("SAML Response invalid");
        }


    }

    private Response processSamlLogin(String responseMessage) throws ConfigurationException, UnmarshallingException, XMLParserException {
        byte[] base64DecodedResponse = Base64.decode(responseMessage);

        //Unmarshalling response
        ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
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
        this.samlSubject = assertion.getSubject().getNameID().getValue();
        this.samlIssuer = assertion.getIssuer().getValue();
        this.samlAudience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();
        this.samlStatusCode = samlResponse.getStatus().getStatusCode().getValue();

        return samlResponse;
    }

    private boolean validateReponse(Response response) throws ValidationException {
            Signature sig = response.getAssertions().get(0).getSignature();

            SignatureValidator validator = new SignatureValidator(credential);
            validator.validate(sig);

            if(!intendedAudience.equalsIgnoreCase(samlAudience)){
                throw new ValidationException("Not intended for the audience sent to");
            }

            return true;
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
            throwException(ex);
        } catch (ParserConfigurationException ex) {
            throwException(ex);
        } catch (UnmarshallingException ex) {
            throwException(ex);;
        } catch (TransformerException ex) {
            throwException(ex);
        } catch (ConfigurationException ex) {
            throwException(ex);
        } catch (XMLParserException ex) {
            throwException(ex);
        } catch (ValidationException ex) {
            throwException(ex);
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
            throwException(ex);
        } catch (ParserConfigurationException ex) {
            throwException(ex);
        } catch (UnmarshallingException ex) {
            throwException(ex);
        } catch (TransformerException ex) {
            throwException(ex);
        } catch (ConfigurationException ex) {
            throwException(ex);
        } catch (XMLParserException ex) {
            throwException(ex);
        } catch (ValidationException ex) {
            throwException(ex);
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

    @Override
    public void init() throws ServletException {
        super.init();



        try {
            this.loadConfiguration();
        } catch (IOException e) {
            throw new ServletException(e);
        }
        try {
            this.loadIdPMetaData();
        } catch (IOException e) {
            throw new ServletException(e);
        } catch (MetadataProviderException e) {
            throw new ServletException(e);
        } catch (SecurityException e) {
            throw new ServletException(e);
        } catch (XMLParserException e) {
            throw new ServletException(e);
        } catch (ParserConfigurationException e) {
            throw new ServletException(e);
        } catch (ConfigurationException e) {
            throw new ServletException(e);
        }

    }

    private void throwException(Exception ex) throws ServletException {
        Logger.getLogger(SamlLoginService.class.getName()).log(Level.SEVERE, null, ex);
        throw new ServletException(ex);
    }

    private void loadIdPMetaData() throws IOException, MetadataProviderException, SecurityException, XMLParserException, ParserConfigurationException, ConfigurationException {

        DefaultBootstrap.bootstrap();
        InputStream metaDataInputStream = new FileInputStream(configuration.getProperty(METADATA_TAG));

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
        criteriaSet.add(new EntityIDCriteria(configuration.getProperty(ENTITYID_TAG)));

        this.credential = (X509Credential) credentialResolver.resolveSingle(criteriaSet);
    }

    private void loadConfiguration() throws IOException {
        String catalinaHome = System.getProperty("catalina.home");
        this.configuration = new Properties();
        configuration.load(new FileInputStream(catalinaHome + CONF_LOCATION));
        this.intendedAudience = configuration.getProperty(AUDIENCE_TAG);
    }
}
