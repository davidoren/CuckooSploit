/*
 *  This script is using JavaScript hooking for profiling of websites, especially
 *  those with malicious content. The following is only a skeleton code. Logic should be added in
 *  order to use it.
 *
 *
 *  Notes & Thoughts:
 *  Malicious websites usually obfuscate their web pages to bypass signature based protection products which work
 *  on static data. Usually, we as researchers manually de-obfuscate the web pages.
 *  JavaScript hooking can be used to gain more information and a better understanding of a website with
 *  less manual de-obfuscation.
 *
 *  Presumptions:
 *  a - Since we are dealing with malicious websites that already try to bypass the static protection engines,
 *      the websites will be obfuscated. Hence, the interesting parts will be added dynamically to the HTML.
 *  b - Components can be added as DOM elements or pass as strings to elements. 
 *      for example: document.createElement() will create a DOM element while document.write() will add a string
 *      that the browser JavaScript engine will handle. the latter will not create DOM elements using the
 *      public API functions themselves (like createElement())
 *  It means that if a string is added to a document.write() like function it can be read statically, 
 *  on the other hand if there's a script that adds elements to the web page then it will do it using DOM element or indirect statically.
 *  To catch the interesting stuff we need to scan strings as well as DOM elements. (unless we are able to create DOM elements from
 *  strings - which is possible in some cases). It could be possible using XMLDOM on IE or by writing a DOM parser. However, we 
 *  currently didn't go in this direction as this is POC.
 *
 *  ##############################################################################################################################
 *  Currently, the architecture works in a way that a logic function is added by hooking it directly to a JavaScript 'core' function.
 *  This makes the code ganular but hard to follow once the logic code becomes big.
 *
 * List of Detections:
 *  1 - Dynamic Iframe detection
 *  2 - ActiveXObject creations
 */
 

// Detect browser by user agent field.
// user agent is easily spoofed so consider methods-signature (duck-typing) or other methods if necessary.
var jsh_is_chrome = navigator.userAgent.indexOf('Chrome') > -1;
var jsh_is_explorer = navigator.userAgent.indexOf('MSIE') > -1 ||  navigator.userAgent.indexOf('Trident') > -1;
var jsh_is_firefox = navigator.userAgent.indexOf('Firefox') > -1;
var jsh_is_safari = navigator.userAgent.indexOf("Safari") > -1;
var jsh_is_Opera = navigator.userAgent.indexOf("Presto") > -1;
if ((jsh_is_chrome)&&(jsh_is_safari)) {jsh_is_safari=false;}

// Main hook function.
function jsh_hook_function(object, property, pre_h_func, post_h_func) 
{
    var original = object[property];
    object[property] = function()
    {
        if (pre_h_func) 
            pre_h_func(arguments);
        
        result = original.apply(this, arguments);
        
        if (post_h_func) 
            post_h_func(arguments, result);
        
        return result;
    }
    return original;
}


// ActiveXObject Wrapper
var original_ActiveXObject;
if (jsh_is_explorer)
{
    original_ActiveXObject = ActiveXObject;

    ActiveXObject = function(name)
    {
        jsh_static_log += "New ActiveXObject named: " + name + " created\r\n";
        // TODO: add logic here
        var original = new original_ActiveXObject(name);
        return original;
    }
}

// Mutation Observer 
// Only logs, logic should be added
var jsh_observer = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        console.log(mutation.type + "\r\n Old Value: " + mutation.oldValue + " \r\n target: " + 
                                    mutation.target + " \r\n innerHTML: ");// + mutation.target.innerHTML);
                    });    
                });            
var jsh_config = { attributes: true,
               childList: true,
               characterData: true,
               subtree: true,
               attributeOldValue: true,
               characterDataOldValue: true
               };


jsh_is_https = function()
{
    if (window && window.location)
        return window.location.protocol.indexOf('https');
    else if (jsh_is_explorer)
        return document.location.protocol.indexOf('https');
}

// based on : http://stackoverflow.com/questions/273789/is-there-a-version-of-javascripts-string-indexof-that-allows-for-regular-expr
// the use of prototype from the original solution removed
jsh_regexIndexOf = function (sentence, regex, startpos)
{
    var indexOf = sentence.substring(startpos || 0).search(regex);
    return (indexOf >= 0) ? (indexOf + (startpos || 0)) : indexOf;
}

jsh_array_contains = function(array, str)
{
    for (var i = 0; i < array.length; i++)
    {
        if (str && array[i] == str.toLowerCase()) return true;
    }
    
    return false;
}

jsh_extract_uri_from_string = function(str)
{
    var patt = /src\s*=\s*[\"\']/i;
    var start = jsh_regexIndexOf(str, patt, 0);
    var end = jsh_regexIndexOf(str, /[\"\']\s*>/i, start);
    return (str.substring(start, end + 1));
}

/********************************************************** LOGGER ***********************************************************/

var jsh_static_log = "/------------------------------ LOG " + document.domain + " -----------------------------\\\n";
jsh_logger = function(text)
{
    return function(){
            jsh_static_log +=  "[-] Function call: " + text + "\n";
            }
}

// Use POST method for server logging.
jsh_post_log_to_server = function()
{
    var protocol;
    if (jsh_is_https())
        protocol = "https://";
    else
        protocol = "http://";
    
    post_server_request = new XMLHttpRequest();
    post_server_request.open("POST", "logger", true);
    post_server_request.setRequestHeader("LOG","xxx")
    post_server_request.send(jsh_static_log);
}


/********************************************************* LOGGER END ********************************************************/


//////////////////////////////////////////////////////////// WINDOW ///////////////////////////////////////////////////////////

// debugging functions
var jsh_hook_standard_functions = false;

/*  WINDOW.ONLOAD
 * window.onload is an event that waits for all resources to load and then execute.
 * Ajax requests are not included and need to be taken care of in a separate way. */
jsh_window_onload_post = function()
{
    console.log('-- all page resources were loaded --');
    console.log(jsh_static_log);
    console.log(jsh_signatures + "*-------------------------------------------------------------------------------*\n");
    
    // TODO: add post resource loading logic here
    jsh_post_log_to_server();
}

if (window.addEventListener) {
    window.addEventListener('load', jsh_window_onload_post, false);
}
else if (window.attachEvent) {
  window.attachEvent('onload', jsh_window_onload_post);
}

if (jsh_hook_standard_functions)
{
    jsh_hook_function(window, 'eval', null, jsh_logger('eval'));
    jsh_hook_function(window, 'createElement', null, jsh_logger('createElement'));
    jsh_hook_function(window, 'escape', null, jsh_logger('escape'));
    jsh_hook_function(window, 'unescape', null, jsh_logger('unescape'));
    jsh_hook_function(window, 'encodeURI', null, jsh_logger('encodeURI'));
    jsh_hook_function(window, 'decodeURI', null, jsh_logger('decodeURI'));
}


///////////////////////////////////// Helper Functions  //////////////////////////////////////

jsh_getElementById = function(args, result)
{
    try
    {
        //jsh_observer.observe(result, jsh_config);
    }
    catch(err)
    {
        // ignore
    }
    return;
}
var original_getElementById = jsh_hook_function(document, 'getElementById', null, jsh_getElementById);

jsh_getElementsByTagName = function(args, result)
{
    //jsh_observer.observe(result, jsh_config);
    return;
}
var original_getElementsByTagName = document.getElementsByTagName; // saved for internal use
jsh_hook_function(document, 'getElementsByTagName', null, jsh_getElementsByTagName);


/////////////////////////////////// Append/Replace Child  ////////////////////////////////////

jsh_body_appendChild_post = function(args)
{   
    var child = args[0];
    
    //if child is a DOM element write it to log
    if (child.tagName)
    {
        console.log(child.parentNode.tagName + " appended child: " + child.tagName.toLowerCase());
    }
}
//jsh_hook_function(Node.prototype, 'appendChild', null, jsh_body_appendChild_post);

jsh_body_replaceChild_post = function(args)
{   
    var child = args[0];
    
    //if child is a DOM element write it to log
    if (child.tagName)
    {
        console.log(child.parentNode.tagName + " replaced child: " + child.tagName.toLowerCase());
    }
}
//jsh_hook_function(Node.prototype, 'replaceChild', null, jsh_body_replaceChild_post);

jsh_body_insertBefore_post = function (args) {
    var child = args[0];

    //if child is a DOM element write it to log
    if (child.tagName) {
        console.log(child.parentNode.tagName + " inserted child: " + child.tagName.toLowerCase());
    }
}
//jsh_hook_function(Node.prototype, 'insertBefore', null, jsh_body_insertBefore_post);


/********************************* Dynamic Iframe Detection *********************************/

// Two fuctions:
// 1 - checks for dynamically added iframe using appendChild / replaceChild / insertBefore
// 2 - checks for dynamically added iframe using document.write
var jsh_open_iframes_in_new_window = false;

jsh_dynamic_iframe_detection_ac_rc = function(args)
{
    var child = args[0];
    
    //if child is a DOM element
    if (child.tagName)
    {
        if (child.tagName.toLowerCase() == 'iframe')
        {
            if (jsh_open_iframes_in_new_window)
            {
                jsh_static_log += "\nOpening dynamically added iframe in a new window:\n" + child.src; 
                // return an empty child for this domain's report
                args[0] = document.createTextNode("");
                window.open(child.src);
                return;
            }
            else
            {
                //jsh_dynamically_added_iframes.push(child);
                jsh_static_log += "\ndynamically added iframe:\n" + child.src;
                return;
            }
        }
        
        var added_ifrs = child.getElementsByTagName('iframe');
        if (added_ifrs.length == 0) return;
        
        for (var i=0; i<added_ifrs.length; i++);
        {
            if (jsh_open_iframes_in_new_window)
            {
                jsh_static_log += "\nOpening dynamically added iframe in a new window:\n" + child.src; 
                // return empty child
                args[0] = document.createTextNode("");
                window.open(child.src);
            }
            else
            {
                jsh_static_log += "\ndynamically added iframe:\n" + added_ifrs[i].src;
            }
        }
    }
}

jsh_dynamic_iframe_detection_dw = function(args)
{
    string_to_check = args[0].toLowerCase();
    if (string_to_check.indexOf('iframe') == -1)
        return;
    
    if (jsh_open_iframes_in_new_window)
    {
        // remove iframe from original request
        args[0] = "";
        
        // extract src
        var source = jsh_extract_uri_from_string(args[0]);
        jsh_static_log += "\nOpening dynamically added iframe in a new window:\n" + source; 
        window.open(source);
    }
    else
    {
        var source = jsh_extract_uri_from_string(string_to_check);
        jsh_static_log += "[-] Dynamically added iframe:\n" + source;
    }
}

jsh_hook_function(Node.prototype, 'appendChild', null, jsh_dynamic_iframe_detection_ac_rc);
jsh_hook_function(Node.prototype, 'replaceChild', null, jsh_dynamic_iframe_detection_ac_rc);
jsh_hook_function(Node.prototype, 'insertBefore', null, jsh_dynamic_iframe_detection_ac_rc);
jsh_hook_function(document, 'write', null, jsh_dynamic_iframe_detection_dw);


/**************************************** DEBUG: TEST ***************************************/

jsh_log_attribute_list = function(element)
{
    for (var i = 0, atts = el.attributes, n = atts.length, arr = []; i < n; i++)
    {
        console.log(atts[i].nodeName);
    }
}
