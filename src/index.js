(function(){
	
	'use strict';

	//jEli Login Service
	//Powered by jEli

	//Update Service
	//Version 1.2.0 Wed 26.10.16

	jEli
	.jModule('jeli.auth.service',{})
	.jProvider('jAuthProvider',jAuthProviderFN)
	.jFactory('jAuthService',["$http","Base64","jAuthProvider","$defer",jAuthServiceFn]);

	function jAuthProviderFN(){
		//Config Object contains service that we support
		//oAuth
		//jDB
		//openID,
		// customLogin
		var config = {
			oauth : false,
			jdb : false,
			openid : false,
			custom : false
		},
		loginType = false,
		loginServiceConfiguration = {},
		registerServiceConfiguration = {},
		loginTrailSettings = {
			count : 3, //default to 3 attempts
			expiresIn : 12 //default to 12 hours
		},
		validationConfigurationStack = {}; //Default Validation Object
		//ValidationFn currently supports minLength,maxLength and emailValidation

		//validate length of a string or obj
		validationConfigurationStack['minlength'] = function(value,requiredLength){
			if(jEli.$isObject(value) || !value){
				return false;
			}

			return String(value).length >= requiredLength;
		};

		validationConfigurationStack['maxlength'] = function(value,requiredLength){
			if(jEli.$isObject(value) || !value){
				return false;
			}
			
			return String(value).length <= requiredLength;
		};

		// validate Email Address
		validationConfigurationStack.emailvalidation = function(val){
			var regExp = /^\w+([\.-]?\w+)*@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

			return regExp.test( val );
		};

		//validate Domain Address
		validationConfigurationStack.domainvalidation = function(domain){

			return /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/.test(domain);
		};

		this.setLoginType  = function( type ){
			if(type && config[type] && !loginType){
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

		this.loginServiceConfiguration = function(obj){
			if(!jEli.$isObject(obj)){
				throw new error('Configuration is expected to be OBJECT not ('+ typeof obj +')');
			}

			loginServiceConfiguration = obj;
		};

		//jDB SAMPLE
		//{DBNAME:"jFrontEndOnly",resource : {serviceHost:"http://localhost/jEliDB/","app_id" : "*","app_secret":"*"}}
		//CustomRegistration
		//{url:"/path_to_login_api"}
		this.registerServiceConfiguration = function(obj){
			if(!jEli.$isObject(obj)){
				throw new error('Configuration is expected to be OBJECT not ('+ typeof obj +')');
			}

			registerServiceConfiguration = obj;
		};

		//Set the number of times an account
		//should be locked after too many attempt
		this.loginTrailSettings = loginTrailSettings;


		/*
			@MMethodName : setValidationConfiguration
			@Params : Configuration Name (STRING)
			@Params : Configuration Function (OBJECT)
			@return : Context (this)
		*/

		this.setValidationConfiguration = function(name, stack){
			if(name && stack){
				validationConfigurationStack[name] = stack;
			}

			return this;
		};

		var authManagerSettings = {
			use : false,
			storage : false,	//only set to true if you want manager to always handle your data on refresh
			storageType : "sessionStorage" //supports only local and sessionStorage
		};

		this.useAuthenticationManager = authManagerSettings;

		this.$get = function(){
			var publicApis = {
				authManagerSettings : authManagerSettings
			};

			publicApis.getLoginConfiguration = function(){
				return loginServiceConfiguration;
			};

			publicApis.getRegisterConfiguration = function(){
				return registerServiceConfiguration;
			};

			publicApis.getLoginType = function(){
				return loginType;
			};

			publicApis.getLoginAttempt = function(force){
				var _stackLoginTrial = window[authManagerSettings.storageType].loginAccountTrial;
				if(_stackLoginTrial && !force){
					//delete the variable from the storage
					delete window[authManagerSettings.storageType].loginAccountTrial;
					return  JSON.parse(_stackLoginTrial);
				}
				
				return  loginTrailSettings;
			};

			//get validationConfigurationStack
			publicApis.getValidationConfiguration = function(){
				return validationConfigurationStack;
			};

			return publicApis;
		};
	}


	//jAuthServiceFn
	function jAuthServiceFn($http,Base64,jAuthProvider,$defer){

		var publicApis = {},
			privateApis = {register:{},login:{},authManager:{}},
			validationFn = jAuthProvider.getValidationConfiguration(),
			loginAccountTrial = jAuthProvider.getLoginAttempt(),
			_stack = {};

			//register JDB
			privateApis.register.jDB = function(postObj,done,fail){
				new jEli.$jDB(postObj.DBNAME,postObj.version || 1)
				.isClientMode()
				.requiresLogin()
				.open(postObj.resource)
				.onSuccess(function(e)
				{
					//set DB
					var $db = e.result;
					//submit user to DB
					$db._users()
					.add(privateApis.register.postBody)
					.onSuccess(done)
					.onError(fail);

					//close the DB
					$db.close(false);
				});
			};

			privateApis.register.custom = function(postObj,done,fail){
				if(postObj.url){
					$http({
						url : postObj.url,
						dataType:'json',
						type: 'POST', 
						contentType : 'application/json',
						data : privateApis.register.postBody
					}).then(done,fail);
				}
			};


			//Login Private Api
			privateApis.login.getHeader = function(){
				return ({
					'Content-Type': 'application/json',
			    	'Accept': 'application/json'
				});
			};


			privateApis.login.oauth = function(postObj,done,fail){
				//login with OAUTH
				var credentials = privateApis.login.postBody,
					headers = this.getHeader(),
					data = 'username=' +  encodeURIComponent(credentials.username) + '&password=' +
			                encodeURIComponent(credentials.password) + '&grant_type=password&scope=read%20write';
			        headers['Authorization'] =  'Basic ' + Base64.encode(postObj.client_id + ':' + postObj.client_secret);

			    //perform task
			    $http.post(postObj.url, data, headers)
			    .then(done,fail);
			};

			//Login with custom
			privateApis.login.custom = function(postObj,done,fail){
				var credentials = privateApis.login.postBody,
					headers = this.getHeader();

				return $http.post(postObj.url, credentials, headers).then(done,fail);
			};


			privateApis.login.jdb = function(postObj,done,fail){
				var credentials = privateApis.login.postBody;
				new jEli.$jDB(postObj.DBNAME,postObj.version || 1)
				.isClientMode()
				.requiresLogin()
				.open(postObj.resource)
				.onSuccess(function(e)
				{
					//set DB
					var $db = e.result;
					//submit user to DB
					$db
					._users()
					.authorize(credentials)
					.onSuccess(done)
					.onError(fail);

					//close the DB
					$db.close(false);
				})
				.onError(fail);
			};


		//Private Api for form validation
		//Iterate through the required validation	

		privateApis.validate = function(type,requiredFields){
			if(!Object.keys(privateApis[type].postBody).length){
				this[type].requiresValidation = true;
				return;
			}

			//check if validationObj exists in PostBody
			var validationModel = Object.keys(requiredFields),
				err = 0;

			validationModel.filter(function(key){
				if(!privateApis[type].postBody[key]){
					err++;
					pushErrorMessage(key,type,"Field is required");
				}
			});

			if(err){
				return;
			}


			//set the validation flag to false
			privateApis[type].validationFailed = false;

			var self = this;
			jEli.forEach(privateApis[type].postBody,function(name,value){
				var _failedValidation =[];
				if(requiredFields[name]){
					_failedValidation = validate(value,requiredFields[name]);
				}

				if(_failedValidation.length){
					
					pushErrorMessage(name,type,_failedValidation);
				}
			});
		};

		//Push the Error Message 
		//Set the Error Flag to true
		function pushErrorMessage(name,type,error){
			privateApis[type].failedValidation[name] = error;
					//set validation flag to true
			privateApis[type].validationFailed = true;
		}


		function validate(value,criteria){
			var errorFound = [];
			//iterate through the criteria
			jEli.forEach(criteria,function(name,obj){
				var passed = false;
				if(validationFn[name.toLowerCase()]){
					passed = (validationFn[name.toLowerCase()] || function(){})(value,obj);
				}
				//if is custom function
				else if(jEli.$isFunction(obj)){
					passed = obj(value);
				}else{}

				if(!passed){
					errorFound.push(name);
				}
			});

			return errorFound;
		}
		/*
				@Reference : Build validation Object based on user Configuration
				@MethodName : setValidationObject
				@Params : type (STRING)
				@return  : Validation Objects (OBJECT)
		*/

		function setValidationObject(type, requiredFields){
			
			if(!requiredFields && !jEli.$isObject(requiredFields)){
				throw new error('Configuration is expected to be Object not ('+ typeof requiredFields +')');
			}

			if(privateApis[type] && jEli.$isObject(requiredFields)){
				//set the validation flag
				privateApis[type].requiresValidation = true;

				//this api is avaliable
				//only when this function is used
				var self = this,
					requiredObjects = {};

				this.validateFields = function(){
					privateApis[type].requiresValidation = false;
					privateApis[type].failedValidation = {};

					//iterate through the postBody data
					//Make sure it passes validation
					privateApis.validate(type,requiredFields);

					return self;
				};
			}

			return this;
		}

		publicApis.register = {
			setData : function(data){
				privateApis.register.postBody = data;
				return this;
			},
			//set Required Fields is Optional
			//Only use it when you want validation
			//Parameter TYPE : OBJ
			//sample 
				// {fullname:{maxLength:{value:50},minLength:{value:40},email:{minLength:{value:10}},validate:function(value){}}}
			setRequiredFields : function(requiredFields){
				
				//trigger ValidationObject Method
				return setValidationObject.apply(this,['register',requiredFields]);

			},
			save : function(success,failure){
				//check if validation is required
				if(privateApis.register.requiresValidation){
					failure({reason:"Form Requires Validation - validateFields : API not called",code:"-101"});

					return;
				}


				if(!privateApis.register.validationFailed){
					var postObj = jAuthProvider.getRegisterConfiguration();
					//check postObj
					if(postObj){
						if(postObj.DBNAME){
							privateApis.register.jDB(postObj,success,failure);
						}else{
							privateApis.register.custom(postObj,success,failure);
						}
					}
				}else{
					failure({reason:"Failed Validation","fields":privateApis.register.failedValidation,code:"-101"});
				}
			}
		};


		//PublicApi to add validation
		publicApis.addValidationRule = function(name,fn){
			if(name && jEli.$isFunction(fn)){
				validationFn[name] = fn;
			}

			return this;
		};


		//PublicApi to Login users
		publicApis.login = {
			setData : function(data){
				privateApis.login.postBody = data;
				return this;
			},
			//set Required Fields is Optional
			//Only use it when you want validation
			//Parameter TYPE : OBJ
			//sample 
				// ["Email","Password"]
			setRequiredFields : function(requiredFields){

				//trigger ValidationObject Method
				return setValidationObject.apply(this,['login',requiredFields]);
			},
			Authorize : function(success,failure){
				//Log user out when Maximum Login
				//is reached
				if(!loginAccountTrial.count){
					failure({reason:"Too Many Login attempt",code:"-100"});
					if(!loginAccountTrial.expiresAt){
						loginAccountTrial.expiresAt = ((+new Date) + (loginAccountTrial.expiresIn * (60 * 60 * 1000)));
					
						//push to stack to lock user
						// should in case user refreshes application
						_stack['loginAccountTrial'] = function(){
							return loginAccountTrial;
						};
					}
	
					return;
				}
				//check if validation is required
				if(privateApis.login.requiresValidation){
					failure({reason:"Form Requires Validation - validateFields : API not called",code:"-101"});

					return;
				}


				if(!privateApis.login.validationFailed){
					var postObj = jAuthProvider.getLoginConfiguration(),
						type = jAuthProvider.getLoginType();
					//check postObj
					privateApis.login[type](postObj,success,function(){
						// reduce the limit of attempt
						loginAccountTrial.count--;
						failure.apply(failure,arguments);
					});
				}else{
					failure({reason:"Failed Validation","fields":privateApis.login.failedValidation,code:"-102"});
				}
			}
		};

		/*
			Application Auth Manager
			Manage your authentication information in one service
			Manage user Authority

			Manager is useAble only when is set to true in configuration
		*/
		if(jAuthProvider.authManagerSettings.use){
			var _userAuthenticationData = {},
				_authenticated = false;
			//check if storage is allow
			getStorageData();
			publicApis.authManager = {
				init : function(){
					_authenticated = true;
				},
				isAuthenticated : function(){
					return _authenticated;
				},
				destroy : function(){
					_userAuthenticationData = {};
					_authenticated = false;
				},
				hasAnyAuthority :  function (authorities,_identity) {
		            if (!_authenticated || !_identity || !_identity.authorities) {
		                return false;
		            }

		            for (var i = 0; i < authorities.length; i++) {
		                if (_identity.authorities.indexOf(authorities[i]) !== -1) {
		                    return true;
		                }
		            }

		            return false;
		        },
		        getData : function(name){
		        	return _userAuthenticationData[name];
		        },
		        storeData : function(name,value){
		        	_userAuthenticationData[name] = value;
		        }
			};

			//set a new stack
			_stack['auth-reload'] = function(){
				return _userAuthenticationData;
			};

			//get the storageData
			function getStorageData(){
				if(jAuthProvider.authManagerSettings.storage){
					_userAuthenticationData = JSON.parse(window[jAuthProvider.authManagerSettings.storageType].getItem('auth-reload') || '{}');
					//remove the cache data
					delete window[jAuthProvider.authManagerSettings.storageType]['auth-reload'];
				}
			}
		};

		/*
			PublicApi for Login Attempt Management
		*/
		publicApis.loginManagement = {
			getExpiresAt : function(){
				return loginAccountTrial.expiresAt;
			},
			$destroy : function(force){
				//reset the user login Attempt to default
				loginAccountTrial = jAuthProvider.getLoginAttempt(force);
			}
		};

		/*
			Service Watcher
		*/
		function initializeWatcher(){
			if("onbeforeunload" in window){
				jEli
				.dom(window)
				.bind('beforeunload',function(e){
					if(jEli.dom.support.localStorage){
						for(var stack in _stack){
							//store the ref data to be retrieve
							window[jAuthProvider.authManagerSettings.storageType].setItem(stack,JSON.stringify(_stack[stack]()));
						}
					}
				});
			}
		}

		//initialize the storage watcher only when set to true
		initializeWatcher();


		return publicApis;
	}
	
})();