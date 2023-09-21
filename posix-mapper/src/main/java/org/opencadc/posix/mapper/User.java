package org.opencadc.posix.mapper;

import jakarta.persistence.*;


@NamedQueries({
        @NamedQuery(name = "findUserByUsername", query = "SELECT u FROM Users u WHERE u.username = :username"),
})
@Entity(name = "Users")
@Table(name = "Users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "users_uid_seq1")
    @SequenceGenerator(name = "users_uid_seq1", sequenceName = "users_uid_seq1", allocationSize = 1)
    private int uid;

    private String username;


    public User() {
    }

    public User(String username) {
        this.username = username;
    }

    public int getUid() {
        return uid;
    }

    public void setUid(int uid) {
        this.uid = uid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        return "User{" +
                "uid=" + uid +
                ", username='" + username + '\'' +
                '}';
    }
}