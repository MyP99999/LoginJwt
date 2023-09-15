/*
 * This file is generated by jOOQ.
 */
package com.example.EvidenNewsAggregator.entities.tables.records;


import com.example.EvidenNewsAggregator.entities.tables.Articles;

import java.time.LocalDate;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record11;
import org.jooq.Row11;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class ArticlesRecord extends UpdatableRecordImpl<ArticlesRecord> implements Record11<Integer, String, LocalDate, String, Integer, String, String, Byte, String, Integer, Integer> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>evidennewsaggregator.articles.article_id</code>.
     */
    public ArticlesRecord setArticleId(Integer value) {
        set(0, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.article_id</code>.
     */
    public Integer getArticleId() {
        return (Integer) get(0);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.title</code>.
     */
    public ArticlesRecord setTitle(String value) {
        set(1, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.title</code>.
     */
    public String getTitle() {
        return (String) get(1);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.date</code>.
     */
    public ArticlesRecord setDate(LocalDate value) {
        set(2, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.date</code>.
     */
    public LocalDate getDate() {
        return (LocalDate) get(2);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.description</code>.
     */
    public ArticlesRecord setDescription(String value) {
        set(3, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.description</code>.
     */
    public String getDescription() {
        return (String) get(3);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.rating</code>.
     */
    public ArticlesRecord setRating(Integer value) {
        set(4, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.rating</code>.
     */
    public Integer getRating() {
        return (Integer) get(4);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.source_link</code>.
     */
    public ArticlesRecord setSourceLink(String value) {
        set(5, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.source_link</code>.
     */
    public String getSourceLink() {
        return (String) get(5);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.name</code>.
     */
    public ArticlesRecord setName(String value) {
        set(6, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.name</code>.
     */
    public String getName() {
        return (String) get(6);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.approved</code>.
     */
    public ArticlesRecord setApproved(Byte value) {
        set(7, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.approved</code>.
     */
    public Byte getApproved() {
        return (Byte) get(7);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.image</code>.
     */
    public ArticlesRecord setImage(String value) {
        set(8, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.image</code>.
     */
    public String getImage() {
        return (String) get(8);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.category_id</code>.
     */
    public ArticlesRecord setCategoryId(Integer value) {
        set(9, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.category_id</code>.
     */
    public Integer getCategoryId() {
        return (Integer) get(9);
    }

    /**
     * Setter for <code>evidennewsaggregator.articles.user_id</code>.
     */
    public ArticlesRecord setUserId(Integer value) {
        set(10, value);
        return this;
    }

    /**
     * Getter for <code>evidennewsaggregator.articles.user_id</code>.
     */
    public Integer getUserId() {
        return (Integer) get(10);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<Integer> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Record11 type implementation
    // -------------------------------------------------------------------------

    @Override
    public Row11<Integer, String, LocalDate, String, Integer, String, String, Byte, String, Integer, Integer> fieldsRow() {
        return (Row11) super.fieldsRow();
    }

    @Override
    public Row11<Integer, String, LocalDate, String, Integer, String, String, Byte, String, Integer, Integer> valuesRow() {
        return (Row11) super.valuesRow();
    }

    @Override
    public Field<Integer> field1() {
        return Articles.ARTICLES.ARTICLE_ID;
    }

    @Override
    public Field<String> field2() {
        return Articles.ARTICLES.TITLE;
    }

    @Override
    public Field<LocalDate> field3() {
        return Articles.ARTICLES.DATE;
    }

    @Override
    public Field<String> field4() {
        return Articles.ARTICLES.DESCRIPTION;
    }

    @Override
    public Field<Integer> field5() {
        return Articles.ARTICLES.RATING;
    }

    @Override
    public Field<String> field6() {
        return Articles.ARTICLES.SOURCE_LINK;
    }

    @Override
    public Field<String> field7() {
        return Articles.ARTICLES.NAME;
    }

    @Override
    public Field<Byte> field8() {
        return Articles.ARTICLES.APPROVED;
    }

    @Override
    public Field<String> field9() {
        return Articles.ARTICLES.IMAGE;
    }

    @Override
    public Field<Integer> field10() {
        return Articles.ARTICLES.CATEGORY_ID;
    }

    @Override
    public Field<Integer> field11() {
        return Articles.ARTICLES.USER_ID;
    }

    @Override
    public Integer component1() {
        return getArticleId();
    }

    @Override
    public String component2() {
        return getTitle();
    }

    @Override
    public LocalDate component3() {
        return getDate();
    }

    @Override
    public String component4() {
        return getDescription();
    }

    @Override
    public Integer component5() {
        return getRating();
    }

    @Override
    public String component6() {
        return getSourceLink();
    }

    @Override
    public String component7() {
        return getName();
    }

    @Override
    public Byte component8() {
        return getApproved();
    }

    @Override
    public String component9() {
        return getImage();
    }

    @Override
    public Integer component10() {
        return getCategoryId();
    }

    @Override
    public Integer component11() {
        return getUserId();
    }

    @Override
    public Integer value1() {
        return getArticleId();
    }

    @Override
    public String value2() {
        return getTitle();
    }

    @Override
    public LocalDate value3() {
        return getDate();
    }

    @Override
    public String value4() {
        return getDescription();
    }

    @Override
    public Integer value5() {
        return getRating();
    }

    @Override
    public String value6() {
        return getSourceLink();
    }

    @Override
    public String value7() {
        return getName();
    }

    @Override
    public Byte value8() {
        return getApproved();
    }

    @Override
    public String value9() {
        return getImage();
    }

    @Override
    public Integer value10() {
        return getCategoryId();
    }

    @Override
    public Integer value11() {
        return getUserId();
    }

    @Override
    public ArticlesRecord value1(Integer value) {
        setArticleId(value);
        return this;
    }

    @Override
    public ArticlesRecord value2(String value) {
        setTitle(value);
        return this;
    }

    @Override
    public ArticlesRecord value3(LocalDate value) {
        setDate(value);
        return this;
    }

    @Override
    public ArticlesRecord value4(String value) {
        setDescription(value);
        return this;
    }

    @Override
    public ArticlesRecord value5(Integer value) {
        setRating(value);
        return this;
    }

    @Override
    public ArticlesRecord value6(String value) {
        setSourceLink(value);
        return this;
    }

    @Override
    public ArticlesRecord value7(String value) {
        setName(value);
        return this;
    }

    @Override
    public ArticlesRecord value8(Byte value) {
        setApproved(value);
        return this;
    }

    @Override
    public ArticlesRecord value9(String value) {
        setImage(value);
        return this;
    }

    @Override
    public ArticlesRecord value10(Integer value) {
        setCategoryId(value);
        return this;
    }

    @Override
    public ArticlesRecord value11(Integer value) {
        setUserId(value);
        return this;
    }

    @Override
    public ArticlesRecord values(Integer value1, String value2, LocalDate value3, String value4, Integer value5, String value6, String value7, Byte value8, String value9, Integer value10, Integer value11) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        value6(value6);
        value7(value7);
        value8(value8);
        value9(value9);
        value10(value10);
        value11(value11);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached ArticlesRecord
     */
    public ArticlesRecord() {
        super(Articles.ARTICLES);
    }

    /**
     * Create a detached, initialised ArticlesRecord
     */
    public ArticlesRecord(Integer articleId, String title, LocalDate date, String description, Integer rating, String sourceLink, String name, Byte approved, String image, Integer categoryId, Integer userId) {
        super(Articles.ARTICLES);

        setArticleId(articleId);
        setTitle(title);
        setDate(date);
        setDescription(description);
        setRating(rating);
        setSourceLink(sourceLink);
        setName(name);
        setApproved(approved);
        setImage(image);
        setCategoryId(categoryId);
        setUserId(userId);
    }
}
