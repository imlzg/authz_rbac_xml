package org.gaozou.kevin.rbac.test;

import junit.framework.TestCase;
import org.gaozou.kevin.rbac.Authorization;

/**
 * Author: george
 * Powered by GaoZou group.
 */
public class AuthzTest extends TestCase {


    public void testAuthz() {
        Authorization authz = Authorization.getInstance();

//        assertTrue(authz.check(new String[]{"user"}, "/test/view.action"));
//        assertTrue(authz.check(new String[]{"user"}, "/test/login.action"));
//        assertTrue(! authz.check(new String[]{"user"}, "/test/edit.action"));
//        assertTrue(authz.check(new String[]{"editor"}, "/test/editEntry.action"));
//
//        assertTrue(! authz.check(new String[]{"admin"}, "/test/view.action"));
//        assertTrue(authz.check(new String[]{"admin"}, "/abc/edit.action"));
//
//
//
//        assertTrue(authz.check(new String[]{"admin"}, "/test/edit.action"));
//        assertTrue(authz.check(new String[]{"admin"}, "/admin/episode"));
//
//
//        assertTrue(authz.check(new String[]{"user"}, "/admin/link/episode"));
//        assertTrue(authz.check(new String[]{"user"}, "/admin/link/host"));
//        assertTrue(! authz.check(new String[]{"admin"}, "/admin/entry"));
//        assertTrue(! authz.check(new String[]{"admin"}, "/admin/host"));



        assertTrue(authz.check(new String[]{"admin"}, "/admin/index"));

    }
}
