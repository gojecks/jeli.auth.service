'use strict';

//jeli Login Service
//Powered by jeli

//Update Service
//Version 1.2.0 Wed 26.10.16

module
    .service('jAuthService', ["$http", "jAuthProvider", jAuthServiceFn]);

//jAuthServiceFn
function jAuthServiceFn($http, jAuthProvider) {
    var publicApis = {},
        privateApis = { register: {}, login: {}, authManager: {}, default: {} },
        validationFn = jAuthProvider.getValidationConfiguration(),
        loginAccountTrial = jAuthProvider.getLoginAttempt(),
        _stack = {};

    //register JDB
    privateApis.register.jDB = function(postObj, done, fail) {
        new jdb(postObj.DBNAME, postObj.version || 1)
            .isClientMode()
            .requiresLogin()
            .open(postObj.resource)
            .onSuccess(function(e) {
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

    privateApis.register.custom = function(postObj, done, fail) {
        if (postObj.url) {
            $http({
                url: postObj.url,
                dataType: 'json',
                type: 'POST',
                contentType: 'application/json',
                data: privateApis.register.postBody
            }).then(done, fail);
        }
    };


    //Login Private Api
    privateApis.login.getHeader = function() {
        return ({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        });
    };


    privateApis.login.oauth = function(postObj, done, fail) {
        //login with OAUTH
        var credentials = privateApis.login.postBody,
            headers = this.getHeader(),
            data = 'username=' + encodeURIComponent(credentials.username) + '&password=' +
            encodeURIComponent(credentials.password) + '&grant_type=password&scope=read%20write';
        headers['Authorization'] = 'Basic ' + btoa(postObj.client_id + ':' + postObj.client_secret);

        //perform task
        $http.post(postObj.url, data, headers)
            .then(done, fail);
    };

    //Login with custom
    privateApis.login.custom = function(postObj, done, fail) {
        var credentials = privateApis.login.postBody,
            headers = this.getHeader();

        return $http.post(postObj.url, credentials, headers).then(done, fail);
    };


    privateApis.login.jdb = function(postObj, done, fail) {
        var credentials = privateApis.login.postBody;
        new jdb(postObj.DBNAME, postObj.version || 1)
            .isClientMode()
            .requiresLogin()
            .open(postObj.resource)
            .onSuccess(function(e) {
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
    var _current = new CurrentInstance(null, pushErrorMessage);
    privateApis.validate = function(type, requiredFields) {
        if (!Object.keys(privateApis[type].postBody).length) {
            this[type].emptyPostBody = true;
            return;
        }

        //check if validationObj exists in PostBody
        var validationModel = Object.keys(requiredFields),
            err = 0;

        validationModel.forEach(function(key) {
            if (!privateApis[type].postBody.hasOwnProperty(key)) {
                err++;
                pushErrorMessage(key, type, "Field is required");
            }
        });

        if (err) {
            return;
        }

        //set the validation flag to false
        privateApis[type].validationFailed = false;
        _current.pending.count = validationModel.length;
        validationModel.forEach(function(name) {
            validate(privateApis[type].postBody[name], requiredFields[name], name);
        });
    };

    //Push the Error Message 
    //Set the Error Flag to true
    function pushErrorMessage(name, type, error) {
        privateApis[type].failedValidation[name] = error;
        //set validation flag to true
        privateApis[type].validationFailed = true;
    }


    /**
     * 
     * @param {*} value 
     * @param {*} criteria 
     * @param {*} par 
     */
    function validate(value, criteria, par) {
        //iterate through the criteria
        var _criteria = Object.keys(criteria);
        _current.add(par, _criteria.length);
        _criteria.forEach(function(name) {
            var passed = false,
                obj = criteria[name];
            if (validationFn.hasOwnProperty(name.toLowerCase())) {
                passed = (validationFn[name.toLowerCase()] || function() {})(value, obj);
            }
            //if is custom function
            else if (jeli.$isFunction(obj)) {
                passed = obj(value);
            }

            /**
             * check if passed && passed is a promise
             */
            if (jeli.$isObject(passed) && jeli.$isEqual('$ajax', name)) {
                return _current.registerAjax(passed, obj, par, name);
            }

            _current.rem(passed, par, name);
        });
    }

    /*
    		@Reference : Build validation Object based on user Configuration
    		@MethodName : setValidationObject
    		@Params : type (STRING)
    		@return  : Validation Objects (OBJECT)
    */

    function setValidationObject(type, requiredFields) {
        if (!requiredFields && !jeli.$isObject(requiredFields)) {
            throw new error('Configuration is expected to be Object not (' + typeof requiredFields + ')');
        }

        /**
         * hold the current running process instance
         */
        _current.clean();
        _current.type = type;

        if (privateApis[type] && jeli.$isObject(requiredFields)) {
            //set the validation flag
            privateApis[type].requiresValidation = true;

            //this api is avaliable
            //only when this function is used
            var self = this,
                requiredObjects = {};

            this.validateFields = function() {
                privateApis[type].requiresValidation = false;
                privateApis[type].failedValidation = {};
                //iterate through the postBody data
                //Make sure it passes validation
                privateApis.validate(type, requiredFields);

                return self;
            };
        }

        return this;
    }


    /**
     * setData Api
     */

    function setData(type) {
        return function(data) {
            privateApis[type].postBody = data;
            return this;
        };
    }

    /**
     * setRequiredFields Api
     */

    function setRequiredFields(type) {
        return function(requiredFields) {
            //trigger ValidationObject Method
            return setValidationObject.apply(this, [type, requiredFields]);
        };
    }

    /**
     * Registration Validation Instance
     */

    publicApis.register = {
        setData: setData('register'),
        //set Required Fields is Optional
        //Only use it when you want validation
        //Parameter TYPE : OBJ
        //sample 
        // {fullname:{maxLength:{value:50},minLength:{value:40},email:{minLength:{value:10}},validate:function(value){}}}
        setRequiredFields: setRequiredFields('register'),
        save: function(success, failure) {
            //check if validation is required
            if (privateApis.register.requiresValidation) {
                failure({ reason: "Form Requires Validation - validateFields : API not called", code: -101 });
                return;
            }

            /**
             * only return when there is a pending validation
             */
            if (_current.pending.count) {
                _current.resolve = resolve;
                return;
            }

            function resolve() {
                if (!privateApis.register.validationFailed) {
                    var postObj = jAuthProvider.getRegisterConfiguration();
                    //check postObj
                    if (postObj) {
                        if (postObj.DBNAME) {
                            privateApis.register.jDB(postObj, success, failure);
                        } else {
                            privateApis.register.custom(postObj, success, failure);
                        }
                    }
                } else {
                    failure({ reason: "Failed Validation", "fields": privateApis.register.failedValidation, code: -102 });
                }
            }

            resolve();
        }
    };


    //PublicApi to add validation
    publicApis.addValidationRule = function(name, fn) {
        if (name && jeli.$isFunction(fn)) {
            validationFn[name] = fn;
        }

        return this;
    };




    //PublicApi to Login users
    publicApis.login = {
        setData: setData('login'),
        //set Required Fields is Optional
        //Only use it when you want validation
        //Parameter TYPE : OBJ
        //sample 
        // ["Email","Password"]
        setRequiredFields: setRequiredFields('login'),
        Authorize: function(success, failure) {
            //Log user out when Maximum Login
            //is reached
            if (!loginAccountTrial.count) {
                failure({ reason: "Too Many Login attempt", code: "-100" });
                if (!loginAccountTrial.expiresAt) {
                    loginAccountTrial.expiresAt = ((+new Date) + (loginAccountTrial.expiresIn * (60 * 60 * 1000)));

                    //push to stack to lock user
                    // should in case user refreshes application
                    _stack['loginAccountTrial'] = function() {
                        return loginAccountTrial;
                    };
                }

                return;
            }
            //check if validation is required
            if (privateApis.login.requiresValidation) {
                failure({ reason: "Form Requires Validation - validateFields : API not called", code: -101 });

                return;
            }


            if (!privateApis.login.validationFailed) {
                var postObj = jAuthProvider.getLoginConfiguration(),
                    type = jAuthProvider.getLoginType();
                //check postObj
                privateApis.login[type](postObj, success, function() {
                    // reduce the limit of attempt
                    loginAccountTrial.count--;
                    failure.apply(failure, arguments);
                });
            } else {
                failure({ reason: "Failed Validation", "fields": privateApis.login.failedValidation, code: -102 });
            }
        }
    };

    /**
     * Use validation without actions
     */
    publicApis.default = {
        setRequiredFields: setRequiredFields('default'),
        setData: setData('default'),
        then: function(success, error) {
            error = error || function() {};
            success = success || function() {};
            //check if validation is required
            if (privateApis.default.requiresValidation) {
                error({ reason: "Form Requires Validation - validateFields : API not called", code: -101 });
                return;
            }

            if (privateApis.default.emptyPostBody) {
                error({ reason: "All form field is empty", code: -100 });
                return;
            }

            /**
             * only return when there is a pending validation
             */
            if (_current.pending.count) {
                _current.resolve = resolve;
                return;
            }

            function resolve() {
                if (!privateApis.default.validationFailed) {
                    success();
                } else {
                    error({ reason: "Failed Validation", "fields": privateApis.default.failedValidation, code: -102 });
                }
            }

            resolve();
        }
    };

    /*
    	Application Auth Manager
    	Manage your authentication information in one service
    	Manage user Authority

    	Manager is useAble only when is set to true in configuration
    */
    if (jAuthProvider.authManagerSettings.use) {
        var _userAuthenticationData = {},
            _authenticated = false;
        //check if storage is allow
        getStorageData();
        publicApis.authManager = {
            init: function() {
                _authenticated = true;
            },
            isAuthenticated: function() {
                return _authenticated;
            },
            destroy: function() {
                _userAuthenticationData = {};
                _authenticated = false;
            },
            hasAnyAuthority: function(authorities, _identity) {
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
            getData: function(name) {
                return _userAuthenticationData[name];
            },
            storeData: function(name, value) {
                _userAuthenticationData[name] = value;
            },
            removeData: function(name) {
                delete _userAuthenticationData[name];
            },
            onBeforeUnload: onBeforeUnload
        };

        //set a new stack
        _stack['auth-reload'] = function() {
            return _userAuthenticationData;
        };

        //get the storageData
        function getStorageData() {
            if (jAuthProvider.authManagerSettings.storage) {
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
        getExpiresAt: function() {
            return loginAccountTrial.expiresAt;
        },
        $destroy: function(force) {
            //reset the user login Attempt to default
            loginAccountTrial = jAuthProvider.getLoginAttempt(force);
        }
    };

    /**
     * 
     */

    function onBeforeUnload() {
        if (jAuthProvider.authManagerSettings.storage && !!window[jAuthProvider.authManagerSettings.storage]) {
            for (var stack in _stack) {
                //store the ref data to be retrieve
                window[jAuthProvider.authManagerSettings.storageType].setItem(stack, JSON.stringify(_stack[stack]()));
            }
        }
    }

    /**
     * 
     * @param {*} name 
     * @param {*} fn 
     */
    onBeforeUnload.addToStack = function(name, fn) {
        if (_stack && !_stack.hasOwnProperty(name) && jeli.$isFunction(fn)) {
            _stack[name] = fn;
        }
    };

    /**
     * 
     * @param {*} stackName 
     */
    onBeforeUnload.removeFromStack = function(stackName) {
        if (_stack.hasOwnProperty(stackName)) {
            delete _stack[stackName];
        }
    };

    /*
    	Service Watcher
    */
    function initializeWatcher() {
        if ("onbeforeunload" in window) {
            window.addEventListener('beforeunload', onBeforeUnload);
        }
    }

    //initialize the storage watcher only when set to true
    initializeWatcher();


    return publicApis;
}