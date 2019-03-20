    /**
     * 
     * @param {*} type 
     * @param {*} error 
     */
    function CurrentInstance(type, error) {
        this.type = type;
        this.pending = {
            count: 0,
            fields: {}

        };
        this.hasAjax = false;
        this.add = function(field, len) {
            this.pending.fields[field] = {
                count: len,
                types: []
            };
        };

        this.rem = function(passed, field, type) {
            this.pending.fields[field].count--;
            if (!passed) {
                // remove the object from Dict
                this.pending.fields[field].types.push(type);
            }

            /**
             * finished resolving but have some errors
             * push to the error domain
             */
            if (!this.pending.fields[field].count) {
                if (this.pending.fields[field].types.length) {
                    error(field, this.type, this.pending.fields[field].types);
                }
                this.pending.count--;
            }

            if (!this.pending.count && this.hasAjax && this.resolve) {
                /**
                 * trigger when no pending status
                 */
                this.resolve();
            }
        }
    }

    CurrentInstance.prototype.clean = function() {
        this.pending = {
            count: 0,
            fields: {}

        };

        this.hasAjax = false;
        this.resolve = null;
    };

    CurrentInstance.prototype.registerAjax = function(AjaxInstance, Request, field, name) {
        this.hasAjax = true;
        var _this = this;
        AjaxInstance.then(function(res) {
            _this.rem((Request.onsuccess || function() { return true; })(res), field, name);
        }, function(res) {
            _this.rem((Request.onerror || function() { return false; })(res), field, name);
        });
    }