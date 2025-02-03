package cl.nava.springsecurityjwt.repositories;

import cl.nava.springsecurityjwt.models.UsersModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IUsersRepository extends JpaRepository<UsersModel, Long> {
    // Method to search for a user by name
    Optional<UsersModel> findByUserName(String username);
    // Method to verify whether a user exists in our database
    Boolean existsByUserName(String username);
}
