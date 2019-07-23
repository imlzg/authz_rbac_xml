package org.gaozou.kevin.rbac;

import org.dom4j.Document;
import org.dom4j.Element;
import org.gaozou.kevin.utility.AntStyleMatch;
import org.gaozou.kevin.utility.ResourceUtil;
import org.gaozou.kevin.utility.StringUtil;
import org.gaozou.kevin.utility.XMLUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Author: george
 * Powered by GaoZou group.
 */
public class Authorization {
    private static final Logger log = LoggerFactory.getLogger(Authorization.class);

    private static String configFile = "authorization.xml";
    private static Authorization instance;

    private Document authzDOM;
    private Map<String, String> privActMap;
    private Map<String, String> roleRgtMap;

    private Authorization() {
        initialize();
    }

    public static Authorization getInstance() {
        if (null == instance) instance = new Authorization();
        return instance;
    }


    public static Set<String> getAuthzRoles() {
        return Authorization.getInstance().getRoleRgtMap().keySet();
    }
    public static String getConfigFile() {
        return configFile;
    }
    public static void setConfigFile(String config) {
        configFile = config;
    }

    public Document getAuthzDOM() {
        return authzDOM;
    }
    public void setAuthzDOM(Document authzDOM) {
        this.authzDOM = authzDOM;
    }

    public Map<String, String> getPrivActMap() {
        return privActMap;
    }

    public Map<String, String> getRoleRgtMap() {
        return roleRgtMap;
    }

    public boolean check(String[] roles, String action) {
        if (StringUtil.isEmpty(action)) return false;

        boolean isPrivate = false;
        for (String value : privActMap.values()) {
            String[] vs = value.split(StringUtil.CROSS);

            if (AntStyleMatch.match(vs[0], action)) {

                if (vs.length == 2) {
                    String[] xs = vs[1].split(String.valueOf(StringUtil.COMMA));
                    boolean isExcludes = false;
                    for (String x : xs) {
                        if (AntStyleMatch.match(x, action)) {
                            isExcludes = true;
                            break;
                        }
                    }
                    if (isExcludes) continue;
                }

                isPrivate = true;
                break;
            }
        }
        if (! isPrivate) return true;


        if (null == roles) return false;
        for (String role : roles) {
            String rightStr = roleRgtMap.get(role);
            if (StringUtil.isEmpty(rightStr)) {
                return false;
            }
            String[] rights = rightStr.split(StringUtil.RHOMB);
            for (String right : rights) {
                String[] vs = right.split(StringUtil.CROSS);
                String[] xs;
                if (vs.length == 2) {
                    xs = vs[1].split(String.valueOf(StringUtil.COMMA));
                } else {
                    xs = new String[0];
                }

                for (String privilege : privActMap.keySet()) {
                    if (AntStyleMatch.match(vs[0], privilege)) {

                        if (vs.length == 2) {
                            boolean isExcludes = false;
                            for (String x : xs) {
                                if (AntStyleMatch.match(x, privilege)) {
                                    isExcludes = true;
                                    break;
                                }
                            }
                            if (isExcludes) continue;
                        }



                        String[] as = privActMap.get(privilege).split(StringUtil.CROSS);

                        if (AntStyleMatch.match(as[0], action)) {
                            if (as.length == 2) {
                                String[] axs = as[1].split(String.valueOf(StringUtil.COMMA));
                                boolean isExcludes = false;
                                for (String x : axs) {
                                    if (AntStyleMatch.match(x, action)) {
                                        isExcludes = true;
                                        break;
                                    }
                                }
                                if (isExcludes) continue;
                            }
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }



    public void refresh() {
        Element root = authzDOM.getRootElement();

        initPrivileges(root.element("privileges"));
        initRoles(root.element("roles"));
    }

    private void initialize() {
        privActMap = new HashMap<String, String>();
        roleRgtMap = new HashMap<String, String>();

        InputStream stream = ResourceUtil.getResourceAsStream(configFile);

        try {
             authzDOM = XMLUtil.read(stream);
        } finally{
            try {
                stream.close();
            } catch (IOException e) {
                log.error("Could not read {}", configFile);
            }
        }
        refresh();
    }

    private void initPrivileges(Element privileges) {
        Iterator iter = privileges.elementIterator("privilege");
        while (iter.hasNext()) {
            Element privilege = (Element) iter.next();

            String name = privilege.attributeValue("name");
            if (StringUtil.isEmpty(name)) continue;
            name = name.trim();

            String action = privilege.attributeValue("action");
            if (StringUtil.isEmpty(action)) continue;
            action = action.trim();

            String excludes = StringUtil.trimAllWhitespace(privilege.attributeValue("excludes"));
            if (! StringUtil.isEmpty(excludes)) action += StringUtil.CROSS + excludes;

            log.debug("init priv-act: {} : {}", name, action);

            privActMap.put(name, action);
        }
    }
    private void initRoles(Element roles) {
        Iterator iter = roles.elementIterator("role");

        while (iter.hasNext()) {
            Element role = (Element) iter.next();

            String name = role.attributeValue("name");
            if (StringUtil.isEmpty(name)) continue;
            name = name.trim();

            Iterator i = role.elementIterator("right");
            StringBuffer rights = new StringBuffer();
            while (i.hasNext()) {
                Element right = (Element) i.next();

                String privilege = right.attributeValue("privilege");
                log.debug("privilege: {}", privilege);
                if (StringUtil.isEmpty(privilege)) continue;
                privilege = privilege.trim();

                String excludes = StringUtil.trimAllWhitespace(right.attributeValue("excludes"));
                if (! StringUtil.isEmpty(excludes)) privilege += StringUtil.CROSS + excludes;

                rights.append(privilege).append(StringUtil.RHOMB);
            }

            log.debug("init role-right: {} : {}", name, rights.substring(0, rights.length() - StringUtil.RHOMB.length()));

            roleRgtMap.put(name, rights.substring(0, rights.length() - StringUtil.RHOMB.length()));
        }

    }
}
