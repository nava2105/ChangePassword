package cl.nava.springsecurityjwt.service;

import cl.nava.springsecurityjwt.factories.IUserFactory;
import cl.nava.springsecurityjwt.models.UsersModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final IUserFactory userFactory;

    @Autowired
    public UserService(IUserFactory userFactory) {
        this.userFactory = userFactory;
    }

    public void create(UsersModel user) {
        userFactory.create(user);
    }

    public List<UsersModel> readAll() {
        // Assume the factory supports returning all users directly or implement a new method.
        throw new UnsupportedOperationException("Not implemented");
    }

    public Optional<UsersModel> readOne(long id) {
        return userFactory.findById(id);
    }

    public void update(UsersModel user) {
        userFactory.update(user);
    }

    public void delete(Long id) {
        userFactory.deleteById(id);
    }
}