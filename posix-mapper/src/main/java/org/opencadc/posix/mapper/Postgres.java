package org.opencadc.posix.mapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;
import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.hibernate.exception.ConstraintViolationException;
import org.opencadc.posix.mapper.web.PosixInitAction;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;

public class Postgres {

    private static final Logger LOGGER = Logger.getLogger(Postgres.class);
    private static final String DEFAULT_JNDI = "java:comp/env/" + PosixInitAction.JNDI_DATASOURCE;
    private final List<Class<?>> entityClasses = new ArrayList<>();
    private final String defaultSchema;
    private SessionFactory sessionFactory;

    private Postgres(final String defaultSchema) {
        this.defaultSchema = defaultSchema;
    }

    public static Postgres instance(final String defaultSchema) {
        return new Postgres(defaultSchema);
    }

    private Properties properties() {
        Properties properties = new Properties();
        properties.put("hibernate.connection.driver_class", "org.postgresql.Driver");
        properties.put("hibernate.connection.datasource", Postgres.DEFAULT_JNDI);
        if (this.defaultSchema != null) {
            properties.put("hibernate.default_schema", this.defaultSchema);
        }
        properties.put("hibernate.show_sql", Boolean.toString(LOGGER.isDebugEnabled()));
        properties.put("hibernate.format_sql", "true");
        properties.put("hibernate.hbm2ddl.auto", "validate");
        properties.put("hibernate.current_session_context_class",
                "org.hibernate.context.internal.JTASessionContext");
        return properties;
    }

    private Configuration configuration(Properties properties, List<Class<?>> entityClasses) {
        Configuration configuration = new Configuration();
        configuration.addProperties(properties);
        for (Class<?> entityClass : entityClasses) {
            configuration.addAnnotatedClass(entityClass);
        }
        return configuration;
    }

    public Postgres entityClass(Class<?>... entityClasses) {
        this.entityClasses.addAll(Arrays.asList(entityClasses));
        return this;
    }

    public Postgres build() {
        Configuration configuration = configuration(properties(), this.entityClasses);
        sessionFactory = configuration.buildSessionFactory();
        return this;
    }

    public Session open() {
        return this.sessionFactory.openSession();
    }

    public void close() {
        if (this.sessionFactory != null) {
            this.sessionFactory.close();
        }
    }

    public <R> R inSession(Function<Session, R> function) {
        try (final Session session = open()) {
            return function.apply(session);
        }
    }

    public <R> R inTransaction(Function<Session, R> function) {
        try {
            return inSession(session -> {
                session.beginTransaction();
                final R val;
                try {
                    val = function.apply(session);
                } catch (Exception e) {
                    session.getTransaction().rollback();
                    throw e;
                }
                session.getTransaction().commit();
                return val;
            });
        } catch (Exception e) {
            LOGGER.error(e);
            throw e;
        }
    }

    public <T> T save(T entity) {
        try {
            return inTransaction(session -> {
                session.persist(entity);
                return entity;
            });
        } catch (ConstraintViolationException constraintViolationException) {
            final String message = constraintViolationException.getMessage();
            if (message.contains("unique constraint")) {
                throw new IllegalArgumentException(entity.getClass().getSimpleName() + " already exists.");
            } else {
                throw constraintViolationException;
            }
        }
    }

    public <T> T update(T entity) {
        return inTransaction(session -> {
            session.merge(entity);
            return entity;
        });
    }

    public <T> void remove(T entity) {
        inTransaction(session -> {
            session.remove(entity);
            return null;
        });
    }

    public <T> T findById(Class<T> type, Object id) {
        return inTransaction(session -> session.find(type, id));
    }

    public <T> T find(Class<T> type, String queryName, Map<String, Object> criteria) {
        return inTransaction(session -> find(type, queryName, criteria, session));
    }

    private <T> T find(Class<T> type, String queryName, Map<String, Object> criteria, Session session) {
        TypedQuery<T> query = session.createNamedQuery(queryName, type);
        if (null != criteria && !criteria.isEmpty()) {
            for (Map.Entry<String, Object> entry : criteria.entrySet()) {
                query.setParameter(entry.getKey(), entry.getValue());
            }
        }
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    public <T> List<T> findAll(Class<T> type, String queryName, Map<String, Object> criteria) {
        return inTransaction(session -> findAll(type, queryName, criteria, session));
    }

    private <T> List<T> findAll(Class<T> type, String queryName, Map<String, Object> criteria, Session session) {
        TypedQuery<T> query = session.createNamedQuery(queryName, type);
        if (null != criteria && !criteria.isEmpty()) {
            for (Map.Entry<String, Object> entry : criteria.entrySet()) {
                query.setParameter(entry.getKey(), entry.getValue());
            }
        }
        try {
            return query.getResultList();
        } catch (NoResultException e) {
            return new ArrayList<>();
        }
    }
}
