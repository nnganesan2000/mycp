
/*
 mycloudportal - Self Service Portal for the cloud.
 Copyright (C) 2012-2013 Mycloudportal Technologies Pvt Ltd

 This file is part of mycloudportal.

 mycloudportal is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 mycloudportal is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with mycloudportal.  If not, see <http://www.gnu.org/licenses/>.
 */
package in.mycp.controller;

import in.mycp.common.Constant;
import in.mycp.domain.Company;
import in.mycp.domain.Department;
import in.mycp.domain.Infra;
import in.mycp.domain.InfraType;
import in.mycp.domain.ProductCatalog;
import in.mycp.domain.Project;
import in.mycp.domain.Role;
import in.mycp.domain.User;
import in.mycp.persistence.MycpPersistenceServiceImpl;
import in.mycp.remote.ProductService;
import in.mycp.remote.RealmService;
import in.mycp.service.WorkflowImpl4Jbpm;
import in.mycp.utils.Commons;
import in.mycp.web.MailDetailsDTO;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.jbpm.api.ProcessInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import net.tanesha.recaptcha.ReCaptchaImpl;
import net.tanesha.recaptcha.ReCaptchaResponse;
/**
 * 
 * @author Charudath Doddanakatte
 * @author cgowdas@gmail.com
 *
 */

@RequestMapping("/cloud-portal")
@Controller
public class LoginController {
	protected static Logger logger = Logger.getLogger(LoginController.class);

	 @Autowired
	 WorkflowImpl4Jbpm workflowImpl4Jbpm;

	 @Autowired
	 ShaPasswordEncoder passwordEncoder;
	 
	 @Autowired
	 ProductService productService;
	 
	 @Autowired
	 private transient MailSender mailTemplate;
	 
	 @Autowired
	 private RealmService realmService;
	 
	 @Autowired  MycpPersistenceServiceImpl mycpPersistenceService;	 
	@RequestMapping(produces = "text/html")
	public String main(HttpServletRequest req, HttpServletResponse resp) {
		logger.info("login "+req.getQueryString()+" {}{}{} "+req.getRequestURL()+" {}{}{} "+req.getRemoteAddr());
		//HttpSession s = req.getSession(true);
		return "mycplogin";
	}
	
	@RequestMapping(value="recoverPwd", produces = "text/html")
	@ResponseBody
	public String recoverPassword(HttpServletRequest req, HttpServletResponse resp) {
		String email = req.getParameter("mail");
		if (StringUtils.isBlank(email)) {
        	return "<font style=\"color: red;\"> Email cannot be empty</font>";
        }
		List<User> lstUser = realmService.findUsersByEmailEquals(email);
		if(lstUser == null || lstUser.size()==0){
			return "<font style=\"color: red;\"> Your email could not be found </font>";
		} else {
			String newPwd = RandomStringUtils.randomAlphanumeric(6);
			
			User user = lstUser.get(0);
			user.setPassword( passwordEncoder.encodePassword(newPwd, email) );
			user.merge();
			
			MailDetailsDTO mailDetailsDTO = new MailDetailsDTO();
			mailDetailsDTO.setTemplateName("RecoverPwdMailTemplate");
        	mailDetailsDTO.setTo(user.getEmail());
        	//mailDetailsDTO.setToName(user.getFirstName());
        	mailDetailsDTO.setBodyText("Dear "+user.getFirstName()+", Your account password is reset to : "+newPwd);
        	Map<String, Object> variables = new HashMap<String, Object>(); 
		    variables.put("mailDetailsDTO", mailDetailsDTO);
		    ProcessInstance instance = workflowImpl4Jbpm.startProcessInstanceByKey("Mail4Users", variables);
			return "<font style=\"color: #32CD32;\"> Password sent to your email </font>";
		}
	}

	@RequestMapping(value="/validateSignup", produces = "text/html")
	@ResponseBody
	public String validateSignup(HttpServletRequest req, HttpServletResponse resp) {
		try {
			String name = req.getParameter("name");
			String email = req.getParameter("email");
			String password = req.getParameter("password");
			String organization = req.getParameter("organization");
			
			String remoteAddr = req.getRemoteAddr();
			
			if (StringUtils.isBlank(name)) {
            	return "<font style=\"color: red;\"> Name cannot be empty</font>";
            }
			if (StringUtils.isBlank(email)) {
            	return "<font style=\"color: red;\"> Email cannot be empty</font>";
            }
			if (StringUtils.isBlank(password)) {
            	return "<font style=\"color: red;\"> Password cannot be empty</font>";
            }
			if (StringUtils.isBlank(organization)) {
            	return "<font style=\"color: red;\"> Organization cannot be empty</font>";
            }
            
            List<User> lstUsers = User.findUsersByEmailEquals(email).getResultList();
            if (lstUsers != null && lstUsers.size()>0) {
            	return "<font style=\"color: red; \"> User " + email + " exists. Choose a different email Id please.</font>";
            }
            
            try {
                HttpSession session = req.getSession();
    			ReCaptchaImpl reCaptcha = new ReCaptchaImpl();
    			reCaptcha.setPrivateKey(Constant.RECAPTCHA_PVT_KEY);
    			String challenge = req.getParameter("recaptcha_challenge_field");
    			String uresponse = req.getParameter("recaptcha_response_field");
    			ReCaptchaResponse reCaptchaResponse = reCaptcha.checkAnswer(remoteAddr, challenge, uresponse);
    			if (!reCaptchaResponse.isValid()) {
                	return "<font style=\"color: red;\">Captcha phrase does not match</font>";
                }
            } catch (Exception e) {
                logger.error(e.getMessage());
                return e.getMessage();
            }
        } catch (Exception e) {
        	e.printStackTrace();
        	logger.error(e.getMessage());
        	return e.getMessage();
        }
		return "";
	}
	
	@RequestMapping(value="/signup", produces = "text/html")
	public String signup(HttpServletRequest req, HttpServletResponse resp) {
		try {
			String name = req.getParameter("name");
			String email = req.getParameter("email");
			String password = req.getParameter("password");
			String organization = req.getParameter("organization");
	        //Moved the code of inserting values into tables to MycpSignupService.SignUp to make it transactional and called that method below.
            User user=mycpPersistenceService.signup(req);            
	            
            //send signup notification to the user
            MailDetailsDTO mailDetailsDTO = new MailDetailsDTO();
			mailDetailsDTO.setTemplateName("SignupMailTemplate");
        	mailDetailsDTO.setTo(user.getEmail());
        	mailDetailsDTO.setToName(user.getFirstName());
        	Map<String, Object> variables = new HashMap<String, Object>(); 
		    variables.put("mailDetailsDTO", mailDetailsDTO);
		    
		    try{
		    workflowImpl4Jbpm.startProcessInstanceByKey("Mail4Users", variables);
		    }catch(Exception e){
		    	//e.printStackTrace();
		    	logger.error(e.getMessage());
		    }
		    
            if(authenticate(email,password)){
    			return "forward:dash";
            }
        } catch (Exception e) {
        	e.printStackTrace();
        	logger.error(e.getMessage());
        }
		return "mycplogin";
	}

   @Autowired
   AuthenticationManager authenticationManager;
	
	 public boolean authenticate(String username, String password) {
	        	/*List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
	    		in.mycp.domain.User mycpUser =null;*/
	    		try {
	    			/*ShaPasswordEncoder passEncoder = new ShaPasswordEncoder(256);
	    			String encodedPass = passEncoder.encodePassword(password, username);
	    			mycpUser = in.mycp.domain.User
	    					.findUsersByEmailEqualsAndPasswordEqualsAndActiveNot(username, encodedPass, false).getSingleResult();
	    			mycpUser.setLoggedInDate(new Date());
	    			mycpUser = mycpUser.merge();
	    			List<Role> roles = Role.findRolesByIntvalLessThan(mycpUser.getRole().getIntval()+1).getResultList();
	    			//everybody gets role_user
	    			//authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
	    			for (Iterator iterator = roles.iterator(); iterator.hasNext();) {
	    				Role role = (Role) iterator.next();
	    				authorities.add(new GrantedAuthorityImpl(role.getName()));
	    			}*/
	    			
	    			UsernamePasswordAuthenticationToken usernameAndPassword = 
	    	                new UsernamePasswordAuthenticationToken(
	    	                		username, password);
	    			
	    			Authentication auth = authenticationManager.authenticate(usernameAndPassword);
		            SecurityContextHolder.getContext().setAuthentication(auth);
	    			return true;
	    		} catch (Exception e) {
	    			e.printStackTrace();
	    		} 
	    		return false;
	    }
	
   
    public void sendMessage(String mailFrom, String subject, String mailTo, String message) {
        org.springframework.mail.SimpleMailMessage mailMessage = new org.springframework.mail.SimpleMailMessage();
        mailMessage.setFrom(mailFrom);
        mailMessage.setSubject(subject);
        mailMessage.setTo(mailTo);
        mailMessage.setText(message);
        mailTemplate.send(mailMessage);
    }

	
	@RequestMapping(value="/dash", produces = "text/html")
	public String dashboard(HttpServletRequest req, HttpServletResponse resp) {
		logger.info("cloud-portal/dash");
		try {
			User user = Commons.getCurrentUser();
			/*MailDetailsDTO mailDetailsDTO = new MailDetailsDTO();
			mailDetailsDTO.setTemplateName("SignupMailTemplate");
        	mailDetailsDTO.setTo(user.getEmail());
        	mailDetailsDTO.setToName(user.getFirstName());
        	Map<String, Object> variables = new HashMap<String, Object>(); 
		    variables.put("mailDetailsDTO", mailDetailsDTO);
		    ProcessInstance instance =  workflowImpl4Jbpm.startProcessInstanceByKey("Mail4Users", variables);*/
		    
			if(user.getRole().getName().equals(Commons.ROLE.ROLE_USER+"")){
				return "cloud-portal/userdash";
			}else if(user.getRole().getName().equals(Commons.ROLE.ROLE_MANAGER+"")){
				return "cloud-portal/managerdash";
			}else if(user.getRole().getName().equals(Commons.ROLE.ROLE_SUPERADMIN+"")){
				return "cloud-portal/superadmindash";
			}
		} catch (Exception e) {
			//e.printStackTrace();
			logger.info(e.getMessage());
		}
		
		//cant figure out the user role .
		return "mycplogin";
	}
	
	
	
}
