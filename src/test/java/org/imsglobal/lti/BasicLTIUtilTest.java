package org.imsglobal.lti;

import java.io.IOException;
import java.net.URISyntaxException;

import jakarta.servlet.http.HttpServletRequest;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.SimpleOAuthValidator;
import net.oauth.server.OAuthServlet;
import net.oauth.signature.OAuthSignatureMethod;

import org.imsglobal.lti.launch.LtiError;
import org.imsglobal.lti.launch.LtiVerificationResult;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class BasicLTIUtilTest {

		@Test
		public void testGetRealPath() {
				String fixed = BasicLTIUtil.getRealPath("http://localhost/path/blah/", "https://right.com");
				assertEquals("https://right.com/path/blah/", fixed);

				fixed = BasicLTIUtil.getRealPath("https://localhost/path/blah/", "https://right.com");
				assertEquals("https://right.com/path/blah/", fixed);

				fixed = BasicLTIUtil.getRealPath("https://localhost/path/blah/", "http://right.com");
				assertEquals("http://right.com/path/blah/", fixed);

				// Test folks sending in URL with extra stuff...
				fixed = BasicLTIUtil.getRealPath("https://localhost/path/blah/", "https://right.com/path/blah");
				assertEquals("https://right.com/path/blah/", fixed);
		}

		@Test
		public void testValidateMessageFailsWhenNoConsumerKey() throws Exception {

				HttpServletRequest requestMock = mock(HttpServletRequest.class);
				String url = "https://example.com/lti-launch";

				OAuthMessage messageMock = mock(OAuthMessage.class);

				try (MockedStatic<OAuthServlet> oauthServletMock = mockStatic(OAuthServlet.class)) {
						oauthServletMock.when(() -> OAuthServlet.getMessage(requestMock, url))
										.thenReturn(messageMock);

						when(messageMock.getConsumerKey()).thenThrow(new IOException("io exception"));

						LtiVerificationResult result = BasicLTIUtil.validateMessage(requestMock, url, "secret");

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
				}
		}

		@Test
		public void testValidateMessageFailWhenUriIsMalformed() throws Exception {

				HttpServletRequest requestMock = mock(HttpServletRequest.class);
				String url = "https://example.com/lti-launch";

				try (MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {
						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenThrow(new URISyntaxException("", "", 0));

						LtiVerificationResult result = BasicLTIUtil.validateMessage(requestMock, url, "secret");

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
				}
		}

		@Test
		public void testValidateMessageFailOnIOException() throws Exception {

				HttpServletRequest requestMock = mock(HttpServletRequest.class);
				String url = "https://example.com/lti-launch";

				try (MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {
						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenThrow(new IOException(""));

						LtiVerificationResult result = BasicLTIUtil.validateMessage(requestMock, url, "secret");

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
				}
		}

		@Test
		public void testValidateMessageFailOnValidateMessageIOException() throws Exception {

				try (MockedConstruction<SimpleOAuthValidator> sovCtor =
										 mockConstruction(SimpleOAuthValidator.class, (sov, context) -> {
												 doThrow(new IOException("failed"))
																 .when(sov)
																 .validateMessage(any(OAuthMessage.class), any(OAuthAccessor.class));
										 });
						 MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {

						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenReturn("");

						LtiVerificationResult result = BasicLTIUtil.validateMessage(
										mock(HttpServletRequest.class),
										"https://example.com/lti-launch",
										"secret"
						);

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
						Assert.assertNull(result.getLtiLaunchResult());
				}
		}

		@Test
		public void testValidateMessageFailOnValidateMessageOAuthException() throws Exception {

				try (MockedConstruction<SimpleOAuthValidator> sovCtor =
										 mockConstruction(SimpleOAuthValidator.class, (sov, context) -> {
												 doThrow(new OAuthException("failed"))
																 .when(sov)
																 .validateMessage(any(OAuthMessage.class), any(OAuthAccessor.class));
										 });
						 MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {

						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenReturn("");

						LtiVerificationResult result = BasicLTIUtil.validateMessage(
										mock(HttpServletRequest.class),
										"https://example.com/lti-launch",
										"secret"
						);

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
						Assert.assertNull(result.getLtiLaunchResult());
				}
		}

		@Test
		public void testValidateMessageFailOnValidateMessageURISyntaxException() throws Exception {

				try (MockedConstruction<SimpleOAuthValidator> sovCtor =
										 mockConstruction(SimpleOAuthValidator.class, (sov, context) -> {
												 doThrow(new URISyntaxException("failed", "failed"))
																 .when(sov)
																 .validateMessage(any(OAuthMessage.class), any(OAuthAccessor.class));
										 });
						 MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {

						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenReturn("");

						LtiVerificationResult result = BasicLTIUtil.validateMessage(
										mock(HttpServletRequest.class),
										"https://example.com/lti-launch",
										"secret"
						);

						Assert.assertEquals(LtiError.BAD_REQUEST, result.getError());
						Assert.assertEquals(Boolean.FALSE, result.getSuccess());
						Assert.assertNull(result.getLtiLaunchResult());
				}
		}

		@Test
		public void testValidateMessagePass() throws Exception {

				try (MockedConstruction<SimpleOAuthValidator> sovCtor =
										 mockConstruction(SimpleOAuthValidator.class, (sov, context) -> {
												 // validateMessage succeeds
												 doNothing().when(sov).validateMessage(any(OAuthMessage.class), any(OAuthAccessor.class));
										 });
						 MockedStatic<OAuthSignatureMethod> sigMock = mockStatic(OAuthSignatureMethod.class)) {

						sigMock.when(() -> OAuthSignatureMethod.getBaseString(any(OAuthMessage.class)))
										.thenReturn("");

						HttpServletRequest req = mock(HttpServletRequest.class);
						when(req.getParameter("user_id")).thenReturn("pgray");
						when(req.getParameter("roles")).thenReturn("instructor, teacher,administrator");
						when(req.getParameter("lti_version")).thenReturn("lpv1");
						when(req.getParameter("lti_message_type")).thenReturn("lti");
						when(req.getParameter("resource_link_id")).thenReturn("12345");
						when(req.getParameter("context_id")).thenReturn("9876");
						when(req.getParameter("launch_presentation_return_url")).thenReturn("http://example.com/return");
						when(req.getParameter("tool_consumer_instance_guid")).thenReturn("instance_id");

						LtiVerificationResult result = BasicLTIUtil.validateMessage(req, "https://example.com/lti-launch", "secret1");

						Assert.assertNull(result.getError());
						Assert.assertEquals(Boolean.TRUE, result.getSuccess());
						Assert.assertNotNull(result.getLtiLaunchResult());

						Assert.assertEquals("pgray", result.getLtiLaunchResult().getUser().getId());
						Assert.assertEquals(3, result.getLtiLaunchResult().getUser().getRoles().size());
						Assert.assertTrue(result.getLtiLaunchResult().getUser().getRoles().contains("instructor"));
						Assert.assertTrue(result.getLtiLaunchResult().getUser().getRoles().contains("teacher"));
						Assert.assertTrue(result.getLtiLaunchResult().getUser().getRoles().contains("administrator"));

						Assert.assertEquals("lpv1", result.getLtiLaunchResult().getVersion());
						Assert.assertEquals("lti", result.getLtiLaunchResult().getMessageType());
						Assert.assertEquals("12345", result.getLtiLaunchResult().getResourceLinkId());
						Assert.assertEquals("9876", result.getLtiLaunchResult().getContextId());
						Assert.assertEquals("http://example.com/return", result.getLtiLaunchResult().getLaunchPresentationReturnUrl());
						Assert.assertEquals("instance_id", result.getLtiLaunchResult().getToolConsumerInstanceGuid());
				}
		}
}
