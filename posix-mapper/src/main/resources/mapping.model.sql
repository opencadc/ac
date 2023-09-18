CREATE TABLE <schema>.Users
(
    uid      INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    username VARCHAR(255),
    CONSTRAINT pk_users PRIMARY KEY (uid)
);

CREATE TABLE <schema>.Groups
(
    gid       INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    groupname VARCHAR(255),
    CONSTRAINT pk_groups PRIMARY KEY (gid)
);

CREATE TABLE <schema>.Users_groups
(
    Users_uid  INTEGER NOT NULL,
    groups_gid INTEGER NOT NULL
);

ALTER TABLE <schema>.Users_groups
    ADD CONSTRAINT fk_usegro_on_group FOREIGN KEY (groups_gid) REFERENCES <schema>.Groups (gid);

ALTER TABLE <schema>.Users_groups
    ADD CONSTRAINT fk_usegro_on_user FOREIGN KEY (Users_uid) REFERENCES <schema>.Users (uid);

create sequence <schema>.groups_gid_seq1
    start with 10000;

create sequence <schema>.users_uid_seq1
    start with 10000;