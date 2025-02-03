package cl.nava.springsecurityjwt.factories;

import cl.nava.springsecurityjwt.models.UsersModel;

import java.util.Optional;

public interface IUserFactory {
    void create(UsersModel user);
    Optional<UsersModel> findByUserName(String username);
    Optional<UsersModel> findById(Long id);
    boolean existsByUserName(String username);
    void update(UsersModel user);
    void deleteById(Long id);
}