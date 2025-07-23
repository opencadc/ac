package org.opencadc.posix.mapper;

import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Parameter;
import org.hibernate.annotations.Type;
import org.opencadc.gms.GroupURI;
import org.opencadc.posix.mapper.db.GroupIDSequenceGenerator;
import org.opencadc.posix.mapper.db.GroupURIType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;


@NamedQuery(name = "findGroupByURI", query = "SELECT g FROM Groups g WHERE g.groupURI = :groupURI")
@Table(name = "Groups")
@Entity(name = "Groups")
public class Group {
    @Id
    @GeneratedValue(generator = "groups_gid_seq1", strategy = GenerationType.SEQUENCE)
    @GenericGenerator(type = GroupIDSequenceGenerator.class, name = "groups_gid_seq1", parameters = {@Parameter(name = "sequence_name", value = "groups_gid_seq1"), @Parameter(name = "increment_size", value = "1")})
    private Integer gid;

    @Column(unique = true)
    @Type(value = GroupURIType.class)
    private GroupURI groupURI;

    public Group() {
    }

    public Group(GroupURI groupURI) {
        this.groupURI = groupURI;
    }

    public Integer getGid() {
        return gid;
    }

    public void setGid(Integer gid) {
        this.gid = gid;
    }

    public GroupURI getGroupURI() {
        return groupURI;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Group)) {
            return false;
        } else {
            final Group g = (Group) obj;
            return g.groupURI.equals(groupURI);
        }
    }

    @Override
    public String toString() {
        return "Group{" +
                "gid=" + gid +
                ", groupURI='" + groupURI + '\'' +
                '}';
    }
}