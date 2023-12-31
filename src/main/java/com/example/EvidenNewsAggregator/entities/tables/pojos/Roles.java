/*
 * This file is generated by jOOQ.
 */
package com.example.EvidenNewsAggregator.entities.tables.pojos;


import java.io.Serializable;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class Roles implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer roleId;
    private String  name;

    public Roles() {}

    public Roles(Roles value) {
        this.roleId = value.roleId;
        this.name = value.name;
    }

    public Roles(
        Integer roleId,
        String  name
    ) {
        this.roleId = roleId;
        this.name = name;
    }

    /**
     * Getter for <code>evidennewsaggregator.roles.role_id</code>.
     */
    public Integer getRoleId() {
        return this.roleId;
    }

    /**
     * Setter for <code>evidennewsaggregator.roles.role_id</code>.
     */
    public Roles setRoleId(Integer roleId) {
        this.roleId = roleId;
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.roles.name</code>.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Setter for <code>evidennewsaggregator.roles.name</code>.
     */
    public Roles setName(String name) {
        this.name = name;
        return this;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        final Roles other = (Roles) obj;
        if (roleId == null) {
            if (other.roleId != null)
                return false;
        }
        else if (!roleId.equals(other.roleId))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        }
        else if (!name.equals(other.name))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((this.roleId == null) ? 0 : this.roleId.hashCode());
        result = prime * result + ((this.name == null) ? 0 : this.name.hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Roles (");

        sb.append(roleId);
        sb.append(", ").append(name);

        sb.append(")");
        return sb.toString();
    }
}
