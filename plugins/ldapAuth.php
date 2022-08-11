<?php

/**
    * ldapAuth plugin for phplist
    *
    * This file is a part of phplist-ldap-plugin
    *
    * @category  phplist
    * @package   ldapAuth
    * @author    Benoit Donneaux - initial code from bpeabody
    * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License, Version 3
    */

/**
 * This class registers the plugin with phplist and hooks into the authentication and validation
 * of admin users.
 */

class ldapAuth extends phplistPlugin
{
    public $name = 'LDAP Authentication Plugin';
    public $version = '0.1';
    public $enabled = true;
    public $authors = 'Benoit Donneaux, bpeabody and other phpList reporters on Mantis';
    public $description = 'Provides authentication to phpList using LDAP';
    public $documentationUrl = 'https://github.com/digital-me/phplist-plugin-ldap';
    public $authProvider = true;

    private $phplistAuth;

    public function activate()
    {
        global $systemroot;
        require_once $systemroot .'/phpListAdminAuthentication.php';

        $this->phplistAuth = new phpListAdminAuthentication();

        parent::activate();
    }

    /*
    * Implement the methods of the phpListAdminAuthentication class by delegating to an instance of
    * that class.
    */

    public function getPassword($email)
    {
        return $this->phplistAuth->getPassword($email);
    }

    public function validateAccount($id)
    {
        return $this->phplistAuth->validateAccount($id);
    }

    public function adminName($id)
    {
        return $this->phplistAuth->adminName($id);
    }

    public function adminEmail($id)
    {
        return $this->phplistAuth->adminEmail($id);
    }

    public function adminIdForEmail($email)
    {
        return $this->phplistAuth->adminIdForEmail($email);
    }

    public function isSuperUser($id)
    {
        return $this->phplistAuth->isSuperUser($id);
    }

    public function listAdmins()
    {
        return $this->phplistAuth->listAdmins();
    }

    /**
    * New validateLogin() function performs LDAP authentication, if enabled, and
    * passes regular table-based validation to localValidateLogin().
    */
    public function validateLogin($login,$password)
    {

        // get all of the values from the config
        global $ldap_enabled;
        global $ldap_url;
        global $ldap_auth_bind_dn;
        global $ldap_auth_bind_pw;
        global $ldap_all_user_base_dn;
        global $ldap_all_user_pattern;
        global $ldap_all_user_uid_attribute;
        global $ldap_all_user_is_super;
        global $ldap_matching_user_base_dn;
        global $ldap_matching_user_pattern;
        global $ldap_matching_user_uid_attribute;
        global $ldap_except_users;
        global $ldap_default_privs;

        // tables is global
        global $tables;

        // make sure our comparisons against the password
        // field don't do anything funky
        $password = strval($password);

        // only do LDAP if it's enabled
        if ($ldap_enabled) {
            // do not allow blank password
            if (strlen($password) < 1) {
                return array(0, 'Password required');
            }

            // check ldap_except_users to see if this should be forced to be
            // local auth
            if ($ldap_except_users && in_array($login, $ldap_except_users)) {
                return $this->localValidateLogin($login, $password);
            }

            // check LDAP auth for "all_users"
            $myPattern = str_replace("__LOGIN__", $login, $ldap_all_user_pattern);
            $myResult = $this->checkLdapAuth(
                $ldap_url, $ldap_auth_bind_dn, $ldap_auth_bind_pw,
                $ldap_all_user_base_dn,
                $myPattern, $password, $ldap_all_user_uid_attribute
            );

            // check to see if it worked
            if (strval(strtolower($myResult[0])) == $login) {

                // see if there is an existing record
                $admindata = Sql_Fetch_Array_Query(sprintf('select password,disabled,id from %s where loginname = "%s"',$GLOBALS["tables"]["admin"],addslashes($login)));

                // if not found, then we create it
                if (!$admindata) {
                    // create a new record
                    if (! $ldap_default_privs) {
                        $ldap_default_privs = array(
                            'subscribers' => true,
                            'campaigns' => true,
                            'statistics' => true,
                            'settings' => true
                        );
                    }
                    Sql_Query(sprintf('insert into %s (loginname,namelc,email,created,privileges) values("%s","%s","",now(),"%s")',
                    $tables["admin"],addslashes($login),addslashes($login),sql_escape(serialize($ldap_default_privs))));
                    $id = Sql_Insert_Id();
                    $admindata = Sql_Fetch_Array_Query(sprintf('select password,disabled,id from %s where loginname = "%s"',$GLOBALS["tables"]["admin"],addslashes($login)));
                }

                // set disabled flag off (by definition "all_users" means enabled
                // accounts) - this ensures that account control for "all_users" lies
                // in the LDAP directory, not in PHPList
                Sql_Query(sprintf('update %s set disabled = 0 where loginname = "%s"',
                    $tables["admin"],addslashes($login)));

                // set the super-user flag appropriately
                Sql_Query(sprintf('update %s set superuser = '.strval($ldap_all_user_is_super).' where loginname = "%s"',
                    $tables["admin"],addslashes($login)));

                // update table to reflect the email address from the directory
                if (strlen(strval($myResult[2]['mail'][0])) > 0) {
                    Sql_Query(sprintf('update %s set email = "%s" where loginname = "%s"',
                        $tables["admin"],addslashes(strval($myResult[2]['mail'][0])),addslashes($login)));
                }

                // return success
                return array($admindata["id"],"OK");
            }

            // "all_users" auth failed, try again with "matching_users"
            $myPattern = str_replace("__LOGIN__", $login, $ldap_matching_user_pattern);
            $myResult = $this->checkLdapAuth(
                $ldap_url, $ldap_auth_bind_dn, $ldap_auth_bind_pw,
                $ldap_matching_user_base_dn,
                $myPattern, $password, $ldap_matching_user_uid_attribute
            );

            // check to see if it worked this time
            if (strval(strtolower($myResult[0])) == $login) {
                // it worked in LDAP, now check for the database record
                $admindata = Sql_Fetch_Array_Query(sprintf('select password,disabled,id from %s where loginname = "%s"',$GLOBALS["tables"]["admin"],addslashes($login)));

                if ($admindata) {
                    // check for disabled account
                    if ($admindata["disabled"]) {
                        return array(0,"your account has been disabled");
                    }

                    // update table to reflect the email address from the directory
                    if (strlen(strval($myResult[2]['mail'][0])) > 0) {
                        Sql_Query(sprintf('update %s set email = "%s" where loginname = "%s"',
                            $tables["admin"],addslashes(strval($myResult[2]['mail'][0])),addslashes($login)));
                    }

                    // all good, return success
                    return array($admindata["id"],"OK");
                } else {
                    return array(0, "Not allowed to login to phplist");
                }
            }

            //echo $myResult[0] . " - " . $myResult[1];

            // no luck - game over
            return array(0, 'LDAP Authentication failed '. $myResult[1]);
            //return $myResult;

        } else {
            // LDAP not enabled, do local check
            return $this->localValidateLogin($login, $password);
        }
    }

    /**
    * Performs LDAP authentication.  Returns
    * array(value_of_uidAttr, "OK", full_ldap_entry_for_target_user)
    * on success, or array(0, "ERROR MESSAGE DESCRIBING WHAT HAPPENED") on
    * failure. This function checks for LDAP authentication by first binding
    * as a different user, searching to find a "target DN" (the DN
    * that corresponds to the end user's login) and then rebinding
    * with that.
    */
    private function checkLdapAuth(
        $aLdapUrl, // the url used to connect to the LDAP server
        $aBindDn,  // the user to bind as
        $aBindPw,  // the password
        $aBaseDn,  // the base of where to search for the actual target user
        $aFilter,  // the search filter to find the target user's DN
        $aUserPw,  // the password of the target user (used to bind again
                         // after the DN of the target user is found
        $aUidAttr,  // the attribute which contains the login ID
                         // (the text name of the login)
        $aLdapVer = 3 // the ldap version protocol to use
    )
    {
        if (strlen(strval($aBaseDn)) == 0) {
            return array(0, 'Authentication method disabled');
        }

        // do not allow blank password
        $aUserPw = strval($aUserPw);
        if (strlen($aUserPw) < 1) {
            return array(0, 'Password required');
        }

        // cover all bases
        $myResult = array(0, "Unknown error");

        // connect to the LDAP server
        $myLdapConn = ldap_connect($aLdapUrl);

        // specify LDAP version protocol
        ldap_set_option($myLdapConn,LDAP_OPT_PROTOCOL_VERSION,$aLdapVer);
        ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 3);

        // if the connection succeeded
        if ($myLdapConn) {
            // do an LDAP bind
            // if we have a bind dn, use it
            // otherwise bind anonymously
            if (strlen($aBindDn) > 0) {
                $myBindResult = ldap_bind($myLdapConn, $aBindDn, $aBindPw);
            } else {
                $myBindResult = ldap_bind($myLdapConn);
            }
            // check to see if bind failed
            if (!$myBindResult) {
                $myResult = array(0, 'Bind to LDAP server failed');
            } else {
                // bind was fine, keep going
                // search for the user in question
                $myLdapSearchResult = ldap_search($myLdapConn, $aBaseDn, $aFilter);
                //~ var_dump($myLdapSearchResult);
                if ($myLdapSearchResult === false) {
                    $myResult = array(0, 'Error in ldap search');
                } else {
                    // if user was found, try to bind again as that user
                    // get the details about the result entries
                    $myLdapEntries = ldap_get_entries($myLdapConn, $myLdapSearchResult);
                    //~ var_dump($myLdapEntries);
                    if ($myLdapEntries['count'] > 0) {
                        // now try another bind as the user that we found
                        $myBindResult = ldap_bind($myLdapConn, $myLdapEntries[0]['dn'], $aUserPw);
                        if (!$myBindResult) {
                            $myResult = array(0, 'Authentication failed ' . $myLdapEntries[0]['dn']);
                        } else {
                            // all good
                            if (count($myLdapEntries[0]["$aUidAttr"]) > 0) {
                                $myResult = array($myLdapEntries[0]["$aUidAttr"][0], "OK", $myLdapEntries[0]);
                            } else {
                                $myResult = array(0, 'Unable to find attribute');
                            }
                        }
                    } else {
                        $myResult = array(0, 'No such user');
                    }
                }
            }
            // cleanup the connection
            ldap_close($myLdapConn);
        } else {
            // connection failure
            $myResult = array(0, 'Connect failed');
        }

        return $myResult;
    }
    /**
    * For users in $ldap_except_users this method provides a fallback to the authentication method from phpList core
    */
    private function localValidateLogin($login,$password)
    {
        return $this->phplistAuth->validateLogin($login, $password);
    }
}
