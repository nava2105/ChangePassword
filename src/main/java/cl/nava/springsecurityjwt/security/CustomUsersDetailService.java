package cl.nava.springsecurityjwt.security;

import cl.nava.springsecurityjwt.models.RolesModel;
import cl.nava.springsecurityjwt.models.UsersModel;
import cl.nava.springsecurityjwt.repositories.IUsersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUsersDetailService implements UserDetailsService {
    private final IUsersRepository usersRepo;

    @Autowired
    public CustomUsersDetailService(IUsersRepository usersRepo) {
        this.usersRepo = usersRepo;
    }

    // Method for bringing a list of authorities through a list of roles
    public Collection<GrantedAuthority> mapToAuthorities(List<RolesModel> roles){
        return  roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }
    // Method to bring us a user with all his data by means of a username
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UsersModel users = usersRepo.findByUserName(username).orElseThrow(()-> new UsernameNotFoundException("User not found"));
        return new User(users.getUserName(), users.getPassword(), mapToAuthorities(users.getRoles()));
    }
}
