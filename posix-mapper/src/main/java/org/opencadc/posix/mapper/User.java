package org.opencadc.posix.mapper;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;


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

    @Column(unique = true)
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