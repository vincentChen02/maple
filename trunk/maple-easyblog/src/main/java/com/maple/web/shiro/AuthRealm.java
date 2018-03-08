package com.maple.web.shiro;

import com.maple.web.dao.UserDao;
import com.maple.web.model.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Created by TYZ034 on 2018/3/8.
 */
@Component
public class AuthRealm extends AuthorizingRealm {



    @Autowired
    private UserDao userDao;

    /**
     * 用来为当前登陆成功的用户授予权限和角色（已经登陆成功了）
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            PrincipalCollection principals) {
        //获取用户名
        //String username = (String) principals.getPrimaryPrincipal();
        //获取当前用户
        User user = (User) principals.fromRealm(getName()).iterator().next();
        //得到权限字符串
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

//        info.addRoles(roleDao.getRoles(user.getId())
//                .stream().map(role -> role.getName()).collect(Collectors.toList()));
//        info.addStringPermissions(permissionDao.getPermissionByUser(user.getId())
//                .stream().map(permission -> permission.getName()).collect(Collectors.toList()));
        return info;
    }

    /**
     * 用来验证当前登录的用户，获取认证信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken authcToken) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) authcToken;

        User user = null;
//                userDao.findOneByUsername(upToken.getUsername());
        if (user == null) {
            return null;
        } else {
            AuthenticationInfo info = new SimpleAuthenticationInfo(user, user.getUserPwd(), getName());
            return info;
        }
    }

}
