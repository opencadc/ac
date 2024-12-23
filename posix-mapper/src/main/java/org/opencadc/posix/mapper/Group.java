package org.opencadc.posix.mapper;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.opencadc.gms.GroupURI;
import org.opencadc.posix.mapper.db.GroupIDSequenceGenerator;
import org.opencadc.posix.mapper.db.GroupURIType;


@NamedQuery(name = "findGroupByURI", query = "SELECT g FROM Groups g WHERE g.groupURI = :groupURI")
@Table(name = "Groups")
@Entity(name = "Groups")
public class Group {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "groups_gid_seq1")
    @SequenceGenerator(name = "groups_gid_seq1", sequenceName = "groups_gid_seq1", allocationSize = 1)
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