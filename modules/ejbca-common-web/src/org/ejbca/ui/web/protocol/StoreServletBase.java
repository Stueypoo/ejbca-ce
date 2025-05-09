/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;

import jakarta.ejb.EJB;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.ejbca.config.VAConfiguration;
import org.ejbca.util.HTMLTools;

/**
 * Base class for servlets (CRL or Certificate) implementing rfc4378
 */
public abstract class StoreServletBase extends HttpServlet {

    protected static final String SPACE = "|" + StringUtils.repeat("&nbsp;", 5);
    
	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(StoreServletBase.class);

	protected CaCertificateCache certCache;
	
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;

	/**
	 * Called when the servlet is initialized.
	 * @param config see {@link HttpServlet#init(ServletConfig)}
	 * @throws ServletException ServletException
	 */
	@Override
    public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.certCache = CaCertificateCache.INSTANCE;
	}

	/**
	 * Return certificate or CRL for the RFC4387 sHash http parameter
	 * @param sHash sHash http parameter
	 * @param resp HttpServletResponse
	 * @param req HttpServletRequest
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	public abstract void sHash(String sHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;

	/**
	 * Return certificate or CRL for the RFC4387 iHash http parameter
	 * @param iHash iHash http parameter
	 * @param resp HttpServletResponse
	 * @param req HttpServletRequest
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	public abstract void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;

	/**
	 * Return certificate or CRL for the RFC4387 sKIDHash http parameter
	 * @param sKIDHash sKIDHash http parameter
	 * @param resp HttpServletResponse
	 * @param req HttpServletRequest
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	public abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	
	/**
	 * Return certificate or CRL for the RFC4387 sKIDHash http parameter. In this case the alias name has been used to get the parameter.
	 * @param sKIDHash sKIDHash http parameter
	 * @param resp HttpServletResponse
	 * @param req HttpServletRequest
	 * @param name alias name of the object
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	public abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req, String name) throws IOException, ServletException;

	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, java.io.IOException {
        if (log.isTraceEnabled()) {
            log.trace(">doGet()");
        }
        if (!req.getRequestURI().substring(req.getContextPath().length()).contains("search.cgi")) {
            resp.sendRedirect(req.getRequestURI() + "search.cgi");
            return;
        }
        try {
            if (alias(req, resp)) {
                return;
            }
            if (performReload(req, resp)) {
                return;
            }
            if (fromName(req, resp)) {
                return;
            }
            rfcRequest(req, resp);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<doGet()");
            }
        }
    }
	
	private void rfcRequest(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
		// Do actual processing of the protocol
		{
			final String sHash = req.getParameter(RFC4387URL.sHash.toString());
			if ( sHash!=null ) {
				sHash( sHash, resp, req );
				return;
			}
		}{
			final String iHash = req.getParameter(RFC4387URL.iHash.toString());
			if ( iHash!=null ) {
				iHash( iHash, resp, req );
				return;
			}
		}{
			final String sKIDHash = req.getParameter(RFC4387URL.sKIDHash.toString());
			if ( sKIDHash!=null ) {
				sKIDHash(sKIDHash, resp, req );
				return;
			}
		}
		printInfo(resp);
	}

	private boolean alias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final String alias = req.getParameter("setAlias");
		if ( alias==null ) {
			return false;
		}
		if ( !checkIfAutorizedIP(req, resp) ) {
			return true;
		}
		final int ix = alias.indexOf('=');
		if ( ix<1 || alias.length()<=ix+2 ) {
			log.debug("No valid alias definition string: "+alias);
			return true;
		}
		final String key = alias.substring(0, ix).trim();
		final String hash = alias.substring(ix+1).trim();
		if ( !VAConfiguration.sKIDHashSetAlias(key, hash) ) {
			log.error("Not possible to add: "+alias);
			return true;
		}
		log.debug("Alias '"+key+"' defined for hash '"+hash+"'.");
		return true;
	}
	
	private boolean fromName(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
		final String alias = req.getParameter("alias");
		if ( alias==null ) {
			return false;
		}
		final String sKIDHash = VAConfiguration.sKIDHashFromName(alias);
		if ( sKIDHash==null || sKIDHash.length()<1 ) {
			final String m = "No '" + HTMLTools.htmlescape(alias) + "' alias defined in va.properties .";
			resp.sendError(HttpServletResponse.SC_NOT_FOUND, m);
			log.debug(m);
			return true;
		}
		sKIDHash( sKIDHash, resp, req, alias );
		return true;
	}
	
	/**
	 * Reloads the certificate cache, if it was requested.
	 * 
	 * @param req the HttpServletRequest
	 * @param resp the HttpServletResponse
	 * @return false if reload wasn't requested, or true if it was requested (even if it turned out to be unauthorized)
	 */
	private boolean performReload(HttpServletRequest req, HttpServletResponse resp) {
		// We have a command to force reloading of the certificate cache that can only be run from localhost
        // http://localhost:8080/ejbca/publicweb/crls/search.cgi?reloadcache=true
		final boolean doReload = StringUtils.equals(req.getParameter("reloadcache"), "true");
		if ( !doReload ) {
			return false;
		}
		try {
            if ( !checkIfAutorizedIP(req, resp) ) {
            	return true;
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not send error response", e);
        }
		log.info("Reloading certificate and CRL caches due to request from "+req.getRemoteAddr());
		// Reload CA certificates
		certificateStoreSession.reloadCaCertificateCache();
		return true;
	}
	
	/**
	 * Checks if the request originates from localhost
	 * 
     * @param req the HttpServletRequest
     * @param resp the HttpServletResponse
	 * @return true if authorized, or false if not, and sends HttpServletResponse.SC_UNAUTHORIZED
     * @throws IOException if the HttpServletResponse.SC_UNAUTHORIZED response couldn't be sent in case if a negative result
	 */
	private boolean checkIfAutorizedIP(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final String remote = req.getRemoteAddr();
		// localhost in either ipv4 and ipv6
		if ( StringUtils.equals(remote, "127.0.0.1") || StringUtils.equals(remote, "0:0:0:0:0:0:0:1") ) {
			return true;
		}
		log.info("Got reloadcache command from unauthorized ip: "+remote);
		resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	}
	


    /**
     * Print info and download URL of a certificate or CRL. A relative URL with only a query string is used.
     *
     * @param cert certificate
     * @param indent indentation
     * @param pw PrintWriter
     */
	public abstract void printInfo(X509Certificate cert, String indent, PrintWriter pw);

	/**
	 * @return the title of the page
	 */
	public abstract String getTitle();

	private void returnInfoPage(HttpServletResponse response, String info) throws IOException {
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		final PrintWriter writer = response.getWriter();

		writer.println("<html>");
		writer.println("<head>");
		writer.println("<title>"+getTitle()+"</title>");
		writer.println("</head>");
		writer.println("<body>");

		writer.println("<table border=\"0\">");
		writer.println("<tr>");
		writer.println("<td>");
		writer.println("<h1>"+getTitle()+"</h1>");
		writer.println("<p>When searching for certificates you can use iHash, sHash and sKIDHash. iHash is the ASN1 encoded DN of the issuer in a certificate, sHash of the subject and sKIDHash is the subjectKeyIdentifier. If you search with it you get all certificates that has the same issuer, except for the root certificate. You do not find a root certificate if you search with the iHash of the root. It has been assumed that sHash should be used when searching for a root.</p>");
		writer.println("<p>When searching for CRLs you can use iHash and sKIDHash. iHash is the ASN1 encoded DN of the issuer in a certificate and sKIDHash is the subjectKeyIdentifier.");
        writer.println("<br/>To get the latest delta CRL you can append the parameter 'delta='.");
        writer.println("<br/>To get a CRL with a specific CRL number you can append the parameter 'crlnumber=&lt;number&gt;'.</p>");
		writer.println("<hr>");
		writer.println(info);
		writer.println("</td>");
		writer.println("</tr>");
		writer.println("</table>");

		writer.println("</body>");
		writer.println("</html>");
		writer.flush();
	}

	private void printInfo(final HttpServletResponse resp) throws IOException {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new HtmlPrintWriter(sw);
		printInfo(this.certCache.getRootCertificates(), "", pw);
		pw.flush();
		pw.close();
		sw.flush();
		returnInfoPage(resp, sw.toString());
		sw.close();
	}

	private class HtmlPrintWriter extends PrintWriter {

		HtmlPrintWriter(Writer out) {
			super(out);
		}
		@Override
		public void println() {
			super.print("<br/>");
			super.println();
		}
		@Override
		public void println(String s) {
			super.print(s);
			println();
		}
	}
	
	protected abstract void printInfo(X509Certificate[] certs, String indent, PrintWriter pw);
}
