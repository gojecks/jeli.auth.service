	'use strict';

	//jEli Login Service
	//Powered by jEli

	//Update Service
	//Version 1.2.0 Wed 26.10.16

	jEli
	    .jModule('jeli.auth.service', {})
	    .jProvider('jAuthProvider', jAuthProviderFN);

	function jAuthProviderFN() {
	    //Config Object contains service that we support
	    //oAuth
	    //jDB
	    //openID,
	    // customLogin
	    var config = {
	            oauth: false,
	            jdb: false,
	            openid: false,
	            custom: false
	        },
	        loginType = false,
	        loginServiceConfiguration = {},
	        registerServiceConfiguration = {},
	        loginTrailSettings = {
	            count: 3, //default to 3 attempts
	            expiresIn: 12 //default to 12 hours
	        },
	        validationConfigurationStack = {}; //Default Validation Object
	    //ValidationFn currently supports minLength,maxLength and emailValidation

	    //validate length of a string or obj
	    validationConfigurationStack['minlength'] = function(value, requiredLength) {
	        if (jEli.$isObject(value) || !value) {
	            return false;
	        }

	        return String(value).length >= requiredLength;
	    };

	    validationConfigurationStack['maxlength'] = function(value, requiredLength) {
	        if (jEli.$isObject(value) || !value) {
	            return false;
	        }

	        return String(value).length <= requiredLength;
	    };

	    // validate Email Address
	    validationConfigurationStack.emailvalidation = function(val) {
	        var regExp = /^\w+([\.-]?\w+)*@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

	        return regExp.test(val);
	    };

	    // ^	The password string will start this way
	    // (?=.*[a-z])	The string must contain at least 1 lowercase alphabetical character
	    // (?=.*[A-Z])	The string must contain at least 1 uppercase alphabetical character
	    // (?=.*[0-9])	The string must contain at least 1 numeric character
	    // (?=.[!@#\$%\^&])	The string must contain at least one special character, but we are escaping reserved RegEx characters to avoid conflict
	    // (?=.{8,})	The string must be eight characters or longer
	    validationConfigurationStack.domainvalidation = function(domain) {
	        return /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/.test(domain);
	    };

	    /**
	     * @name mediumPasswordStrength
	     * @param {*} passwd 
	     */
	    validationConfigurationStack.mediumpasswordstrength = function(passwd) {
	        return new RegExp("^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})").test(passwd);
	    };

	    /**
	     * @name strongPasswordStrength
	     * @param {*} passwd 
	     */
	    validationConfigurationStack.strongpasswordstrength = function(passwd) {
	        return new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})").test(passwd)
	    };

	    // boolean validation
	    validationConfigurationStack.boolean = function(bool, val) {
	        return bool === val;
	    };

	    /**
	     * $ajax validation
	     * accepted pattern 
	     * 	{
	     * 		resolve : <function > | <string>
	     * 		onsuccess : <function>
	     * 		onerror : <function>
	     * 	}
	     */
	    validationConfigurationStack.$ajax = function(val, def) {
	        if (!jEli.$isObject(def) || !jEli.$isFunction(def.resolve)) {
	            return false;
	        }

	        return def.resolve(val);
	    };

	    this.setLoginType = function(type) {
	        if (type && config[type] && !loginType) {
	            config[type] = true;
	        }

	        loginType = type;
	    };

	    // loginServiceConfiguration
	    //Accepts Object depending on login type
	    // OAUTH SAMPLE
	    //{url : "/oauth/token","client_id":"example","client_secret":"example_secret"}
	    //jDB SAMPLE
	    //{DBNAME:"jFrontEndOnly",resource : {loginMode:1,serviceHost:"http://localhost/jEliDB/","app_id" : "*","app_secret":"*"}}
	    //CustomLogin
	    //{"url":"/path_to_login_api"}

	    this.loginServiceConfiguration = function(obj) {
	        if (!jEli.$isObject(obj)) {
	            throw new error('Configuration is expected to be OBJECT not (' + typeof obj + ')');
	        }

	        loginServiceConfiguration = obj;
	    };

	    //jDB SAMPLE
	    //{DBNAME:"jFrontEndOnly",resource : {serviceHost:"http://localhost/jEliDB/","app_id" : "*","app_secret":"*"}}
	    //CustomRegistration
	    //{url:"/path_to_login_api"}
	    this.registerServiceConfiguration = function(obj) {
	        if (!jEli.$isObject(obj)) {
	            throw new error('Configuration is expected to be OBJECT not (' + typeof obj + ')');
	        }

	        registerServiceConfiguration = obj;
	    };

	    //Set the number of times an account
	    //should be locked after too many attempt
	    this.loginTrailSettings = loginTrailSettings;


	    /*
	    	@MMethodName : setValidationRule
	    	@Params : Configuration Name (STRING)
	    	@Params : Configuration Function (OBJECT)
	    	@return : Context (this)
	    */

	    this.setValidationRule = function(name, stack) {
	        if (name && stack) {
	            validationConfigurationStack[name] = stack;
	        }

	        return this;
	    };

	    var authManagerSettings = {
	        use: false,
	        storage: false, //only set to true if you want manager to always handle your data on refresh
	        storageType: "sessionStorage" //supports only local and sessionStorage
	    };

	    this.useAuthenticationManager = authManagerSettings;

	    this.$get = function() {
	        var publicApis = {
	            authManagerSettings: authManagerSettings
	        };

	        publicApis.getLoginConfiguration = function() {
	            return loginServiceConfiguration;
	        };

	        publicApis.getRegisterConfiguration = function() {
	            return registerServiceConfiguration;
	        };

	        publicApis.getLoginType = function() {
	            return loginType;
	        };

	        publicApis.getLoginAttempt = function(force) {
	            var _stackLoginTrial = window[authManagerSettings.storageType].loginAccountTrial;
	            if (_stackLoginTrial && !force) {
	                //delete the variable from the storage
	                delete window[authManagerSettings.storageType].loginAccountTrial;
	                return JSON.parse(_stackLoginTrial);
	            }

	            return loginTrailSettings;
	        };

	        //get validationConfigurationStack
	        publicApis.getValidationConfiguration = function() {
	            return validationConfigurationStack;
	        };

	        return publicApis;
	    };
	}