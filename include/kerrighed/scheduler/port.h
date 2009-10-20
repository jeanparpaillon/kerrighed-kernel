#ifndef __KRG_SCHEDULER_PORT_H__
#define __KRG_SCHEDULER_PORT_H__

#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/scheduler/pipe.h>
#include <kerrighed/scheduler/global_config.h>

/*
 * A scheduler_port is a scheduler_pipe having at least a scheduler_sink. The
 * sink can connect to another scheduler_pipe having a source.
 *
 * Doing mkdir in a scheduler_port directory creates a new scheduler_port having
 * a source, which type is named after the new subdir name. The creator port's
 * sink is connected to the created port's source.
 *
 * Creating a symlink from an entry of port's directory to another
 * scheduler_pipe directory (currently this is only allowed for probe sources)
 * connects the port's sink to the symlink target's source.
 *
 * In both kind of connections, the connection is publish-subscribe enabled if
 * the port provides an update_value() method and either has no source or
 * its source already has subscribers.
 */

struct scheduler_port;
struct scheduler_port_type;

/**
 * prototype for a port callback that gets the value of a remote lower source
 *
 * @param port		port for which the callback is called
 * @param node		node to get the value from
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			-EAGAIN if the request is pending and the caller should
 *			retry later, or
 *			other negative error code
 */
typedef int port_get_remote_value_t(struct scheduler_port *port,
				    kerrighed_node_t node,
				    void *value_p, unsigned int nr,
				    const void *in_value_p,
				    unsigned int in_nr);

/**
 * prototype for a port type callback that creates a new port
 *
 * @param name		directory name of the new port
 *
 * @return		valid pointer to a new port, or
 *			NULL if no port could be successfully created
 */
typedef struct scheduler_port *port_new_t(const char *name);

/**
 * prototype for a port type callback that destroys a port (for instance frees
 * memory)
 *
 * @param port		port to destroy
 */
typedef void port_destroy_t(struct scheduler_port *);


/*
 * Structure representing a type of port. Must be initialized with
 * SCHEDULER_PORT_TYPE_INIT (for instance through BEGIN_SCHEDULER_PORT_TYPE and
 * SCHEDULER_PORT_* helpers).
 */
struct scheduler_port_type {
	const char *name;
	struct scheduler_sink_type sink_type;
	struct scheduler_pipe_type pipe_type;
	/* method to get the value from a remote node */
	port_get_remote_value_t *get_remote_value;
	/** constructor of ports of this type */
	port_new_t *new;
	/** destructor of ports of this type */
	port_destroy_t *destroy;
	struct list_head list;
};

/* Structure representing a port */
struct scheduler_port {
	struct scheduler_sink sink;
	struct scheduler_pipe pipe;
	struct scheduler_pipe *peer_pipe;
	struct global_config_item global_item;	/** global config item referring
						  * to the connected source */
	struct global_config_attrs global_attrs;
};

struct scheduler_port_attribute;

/* Same limitation as configfs (see SIMPLE_ATTR_SIZE in fs/configfs/file.c) */
#define SCHEDULER_PORT_ATTR_SIZE 4096

/**
 * prototype for a port_attribute callback that reads a port attribute
 *
 * @param port		port which attribute is read
 * @param attr		structure describing the attribute read
 * @param page		4Kbytes buffer to fill in
 *
 * @return		number of bytes written to page, or
 *			negative error code
 */
typedef ssize_t port_attribute_show_t(struct scheduler_port *port,
				      struct scheduler_port_attribute *attr,
				      char *page);
/**
 * prototype for a port_attribute callback that modifies a port attribute
 *
 * @param port		port which attribute is read
 * @param attr		structure describing the attribute read
 * @param buffer	buffer containing the data to modify attr
 * @param count		size in bytes of the modification data
 *
 * @return		number of bytes read from buffer, or
 *			negative error code
 */
typedef ssize_t port_attribute_store_t(struct scheduler_port *port,
				       struct scheduler_port_attribute *attr,
				       const char *buffer, size_t count);

/*
 * Structure representing a scheduler_port attribute. Must be initialized with
 * SCHEDULER_PORT_ATTRIBUTE_INIT.
 */
struct scheduler_port_attribute {
	struct configfs_attribute config;
	/** method to read a custom attribute of a port of this type */
	port_attribute_show_t *show;
	/** method to modify a custom attribute of a port of this type */
	port_attribute_store_t *store;
};

/**
 * Mandatory macro to define a scheduler_port_type. Can be called through
 * the BEGIN_SCHEDULER_PORT_TYPE helper.
 *
 * @param port_type	variable name of the port type
 * @param owner		module providing this port type
 * @param _name		string containing the unique name of this port type
 * @param snk_update_value
 *			method to give to the scheduler_sink of a
 *			port of this type
 * @param snk_value_type
 *			string containing the type name of lower source's values
 * @param snk_value_type_size
 *			size in bytes of a snk_value_type value
 * @param snk_get_param_type
 *			string containing the type name of the parameters for
 *			the sink's get_value() calls, or NULL
 * @param snk_get_param_type_size
 *			size in bytes of a snk_get_param_type parameter
 * @param source_type	optional source type to attach to the
 *			scheduler_pipe_type of this port type
 * @param _get_remote_value
 *			get_remote_value() method of this port type
 * @param _new		creator of ports of this type
 * @param _destroy	destructors of ports of this type
 */
#define SCHEDULER_PORT_TYPE_INIT(port_type, owner, _name,		\
				 snk_update_value,			      \
				 snk_value_type, snk_value_type_size,	      \
				 snk_get_param_type, snk_get_param_type_size, \
				 source_type,				\
				 _get_remote_value,			\
				 _new,					\
				 _destroy)				\
	{								\
		.name = _name,						\
		.sink_type = SCHEDULER_SINK_TYPE_INIT(			\
			snk_update_value,				\
			snk_value_type,					\
			snk_value_type_size,				\
			snk_get_param_type,				\
			snk_get_param_type_size),			\
		.pipe_type = SCHEDULER_PIPE_TYPE_INIT(			\
			owner,						\
			NULL, NULL,					\
			source_type, &port_type.sink_type),		\
		.get_remote_value = _get_remote_value,		\
		.new = _new,					\
		.destroy = _destroy,				\
	}

/*
 * Convenience macros to define a scheduler_port_type
 *
 * These convenience macros should be used the following way:
 *
 * First, implemented methods must be defined using the
 * DEFINE_SCHEDULER_PORT_<method> macros. Second, the scheduler_port_type must
 * be filled using {BEGIN,END}_SCHEDULER_PORT_TYPE and SCHEDULER_PORT_* macros:
 *
 *	BEGIN_SCHEDULER_PORT_TYPE(name),
 *		.SCHEDULER_PORT_VALUE_TYPE(name, type),
 * if needed:
 *		.SCHEDULER_PORT_<method>(name),
 *		.SCHEDULER_PORT_PARAM_TYPE(name, type),
 *		.SCHEDULER_PORT_ATTRS(name, attrs),
 *		...
 * and finally:
 *	END_SCHEDULER_PORT_TYPE(name);
 */

/**
 * Convenience macro to start the definition of a scheduler_port_type. The
 * definition must end with END_SCHEDULER_PORT_TYPE(name). The variable will be
 * called name_type.
 *
 * @param name		name of the scheduler_port type
 */
#define BEGIN_SCHEDULER_PORT_TYPE(_name)			   \
	struct scheduler_port_type _name##_type = {		   \
		.name = #_name,					   \
		.sink_type = SCHEDULER_SINK_TYPE_INIT(NULL,	   \
						      NULL, 0,	   \
						      NULL, 0),	   \
		.pipe_type = SCHEDULER_PIPE_TYPE_INIT(		   \
			THIS_MODULE,				   \
			NULL, NULL,				   \
			NULL, &_name##_type.sink_type)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_UPDATE_VALUE(prefix, name)			\
	__SCHEDULER_SINK_UPDATE_VALUE(prefix sink_type.,		\
				      name##_sink_update_value)

/**
 * Convenience macro to attach a previously defined update_value() method to a
 * scheduler_port type. The update_value() method must have been defined earlier
 * with DEFINE_SCHEDULER_PORT_UPDATE_VALUE(name, ...).
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 */
#define SCHEDULER_PORT_UPDATE_VALUE(name)	\
	__SCHEDULER_PORT_UPDATE_VALUE(, name)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_VALUE_TYPE(prefix, name, type)		\
	__SCHEDULER_SINK_VALUE_TYPE(prefix sink_type., type)

/**
 * Convenience macro to declare the value type of a scheduler port. Must be used
 * within all BEGIN_SCHEDULER_PORT_TYPE sections.
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 * @param type		litteral expression of the value type read by the sink
 */
#define SCHEDULER_PORT_VALUE_TYPE(name, type)		\
	__SCHEDULER_PORT_VALUE_TYPE(, name, type)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_PARAM_TYPE(prefix, name, type)		\
	__SCHEDULER_SINK_PARAM_TYPE(prefix sink_type., type)

/**
 * Convenience macro to declare the parameter type used when calling the
 * get_value() method of a connected source.
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 * @param type		litteral expression of the parameter type
 */
#define SCHEDULER_PORT_PARAM_TYPE(name, type)		\
	__SCHEDULER_PORT_PARAM_TYPE(, name, type)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_SOURCE_TYPE(prefix, name, source_type)		\
	__SCHEDULER_PIPE_SOURCE_TYPE(prefix pipe_type., source_type)

/**
 * Convenience macro to attach a source type to the pipe_type embedded in a
 * scheduler_port_type
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 * @param source_type	source_type to attach
 */
#define SCHEDULER_PORT_SOURCE_TYPE(name, source_type)		\
	__SCHEDULER_PORT_SOURCE_TYPE(, name, source_type)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_GET_REMOTE_VALUE(prefix, name)		\
	prefix get_remote_value = name##_get_remote_value

/**
 * Convenience macro to attach a previously defined get_remte_value() method to
 * a scheduler_port type. The get_remote_value() method must have been defined
 * earlier with DEFINE_SCHEDULER_PORT_GET_REMOTE_VALUE(name, ...).
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 */
#define SCHEDULER_PORT_GET_REMOTE_VALUE(name)		\
	__SCHEDULER_PORT_GET_REMOTE_VALUE(, name)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_NEW(prefix, name)	\
	prefix new = name##_new

/**
 * Convenience macro to attach a previously defined constructor to a port type.
 * The constructor must have been defined earlier and must be called name_new.
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 */
#define SCHEDULER_PORT_NEW(name)		\
	__SCHEDULER_PORT_NEW(, name)

/* Helper to define convenience initializers in super classes */
#define __SCHEDULER_PORT_DESTROY(prefix, name)	\
	prefix destroy = name##_destroy

/**
 * Convenience macro to attach a previously defined destructor to a port type.
 * The destructor must have been defined earlier and must be called
 * name_destroy.
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 */
#define SCHEDULER_PORT_DESTROY(name)		\
	__SCHEDULER_PORT_DESTROY(, name)

/**
 * End the definition of a scheduler_port_type. Must close any
 * BEGIN_SCHEDULER_PORT_TYPE section.
 *
 * @param name		must match the name used with BEGIN_SCHEDULER_PORT_TYPE
 */
#define END_SCHEDULER_PORT_TYPE(name)		\
	}

/**
 * Convenience macro to define an update_value() method for a port.
 * The method will be called name_update_value.
 *
 * @param name		name of the scheduler_port type
 * @param port		name of the port arg of the method
 */
#define DEFINE_SCHEDULER_PORT_UPDATE_VALUE(name, port)			      \
	static void name##_update_value(struct scheduler_port *);	      \
	static void name##_sink_update_value(struct scheduler_sink *sink,     \
					     struct scheduler_source *source) \
	{								      \
		name##_update_value(					      \
			container_of(sink, struct scheduler_port, sink));     \
	}								      \
	static void name##_update_value(struct scheduler_port *port)

/**
 * Convenience macro to define an get_remote_value() method for a port, without
 * parameters given to the source. The method will be called
 * name_get_remote_value.
 *
 * @param name		name of the scheduler_port type
 * @param port		name of the port arg of the method
 * @param value_type	type of the values read by the sink (eg. int)
 * @param value_p	name of the type *arg of the method
 * @param nr_value	name of the array length parameter of the method
 */
#define DEFINE_SCHEDULER_PORT_GET_REMOTE_VALUE(name, port,		      \
					       value_type, value_p, nr_value) \
	static int name##_get_remote_value(struct scheduler_port *,	      \
					   value_type *, int);		      \
	static int name##_get_remote_value_untyped(			      \
		struct scheduler_port *port,				      \
		void *vp, int nr_v,					      \
		const void *pp, int nr_p)				      \
	{								      \
		return name##_get_remote_value(port, vp, nr_v);		      \
	}								      \
	static int name##_get_remote_value(struct scheduler_port *port,       \
					   value_type *value_p, int nr_value)

/**
 * Convenience macro to define an get_remote_value() method for a port, with
 * parameters given to the source. The method will be called
 * name_get_remote_value.
 *
 * @param name		name of the scheduler_port type
 * @param port		name of the port arg of the method
 * @param value_type	type of the values read by the sink (eg. int)
 * @param value_p	name of the type *arg of the method
 * @param nr_value	name of the array length parameter of the method
 * @param param_type	type of the parameters given to the source (eg. int)
 * @param param_p	name of the param_type *arg of the method
 * @param nr_param	name of the parameters array length arg of the method
 */
#define DEFINE_SCHEDULER_PORT_GET_REMOTE_VALUE_WITH_INPUT(		      \
	name, port,							      \
	value_type, value_p, nr_value,					      \
	param_type, param_p, nr_param)					      \
	static int name##_get_remote_value(struct scheduler_port *,	      \
					   value_type *, int,		      \
					   const param_type *, int);	      \
	static int name##_get_remote_value_untyped(			      \
		struct scheduler_port *port,				      \
		void *vp, int nr_v,					      \
		const void *pp, int nr_p)				      \
	{								      \
		return name##_get_remote_value(port, vp, nr_v, pp, nr_p);     \
	}								      \
	static int name##_get_remote_value(				      \
		struct scheduler_port *port,				      \
		value_type *value_p, int nr_value,			      \
		const param_type *param_p, int nr_param)

/* End of convenience macros */

/**
 * Mandatory initializer for a scheduler_port_attribute.
 *
 * @param name		name of the attribute entry in the port directory
 * @param mode		access mode of the attribute entry
 * @param _show		show callback of the attribute
 * @param _store	store callback of the attribute
 */
#define SCHEDULER_PORT_ATTRIBUTE_INIT(name, mode, _show, _store) \
	{							 \
		.config = {					 \
			.ca_name = name,			 \
			.ca_owner = THIS_MODULE,		 \
			.ca_mode = mode				 \
		},						 \
		.show = _show,					 \
		.store = _store					 \
	}

/* Tool functions for port designers */

/**
 * Initialize a scheduler port type
 * Must be called before creating any port of this type. Is called through
 * scheduler_port_type_register().
 *
 * @param type		type to init
 * @param attrs		NULL-terminated array of pointers to custom attributes,
 *			or NULL
 *
 * @return		0 is successful, or
 *			-ENOMEM if no sufficient memory could be allocated
 */
int scheduler_port_type_init(struct scheduler_port_type *type,
			     struct configfs_attribute **attrs);
/**
 * Free the resources allocated at type initialization
 *
 * @param type		type to cleanup
 */
void scheduler_port_type_cleanup(struct scheduler_port_type *type);

/**
 * Initialize and register a new port type
 *
 * @param type		type to register
 * @param attrs		NULL-terminated array of custom configfs_attribute, or
 *			NULL
 *
 * @return		0 if successful,
 *			-ENOMEM if not sufficient memory could be allocated,
 *			-EEXIST if a type of this name is already registered.
 */
int scheduler_port_type_register(struct scheduler_port_type *type,
				 struct configfs_attribute **attrs);
/**
 * Unregister and cleanup a port type. Must be called at module unload *only*.
 *
 * @param type		type to unregister
 */
void scheduler_port_type_unregister(struct scheduler_port_type *type);

/**
 * Initialize a new scheduler_port. Must be called by scheduler_port
 * constructors.
 *
 * @param port		port to initialize
 * @param name		name of the directory of this port. Must match the name
 *			given as argument to the constructor.
 * @param type		type of the new port
 * @param source	optional source of the object embedding port, or NULL
 * @param default_groups
 *			NULL terminated array of custom config_groups displayed
 *			as subdirs of the port, or NULL
 *
 * @return		0 if successful,
 *			negative error code if error
 */
int scheduler_port_init(struct scheduler_port *port,
			const char *name,
			struct scheduler_port_type *type,
			struct scheduler_source *source,
			struct config_group **default_groups);
/**
 * Cleanup a scheduler_port before freeing it. Must be called by the port's
 * destructor.
 *
 * @param port		port to cleanup
 */
void scheduler_port_cleanup(struct scheduler_port *port);

/**
 * Helper to refer to a port through its embedded config_group (for instance
 * to build the default_groups[] array of a parent config_group)
 *
 * @param port		port which config_group address to return
 *
 * @return		address of the embedded config_group of the port
 */
static inline
struct config_group *scheduler_port_config_group(struct scheduler_port *port)
{
	return &port->pipe.config;
}

/* Functions to query a port */

/**
 * Get the value from the source connected to a port
 *
 * @param port		port to query
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			negative error code
 */
static inline
int scheduler_port_get_value(struct scheduler_port *port,
			     void *value_p, unsigned int nr,
			     const void *in_value_p, unsigned int in_nr)
{
	return scheduler_sink_get_value(&port->sink,
					value_p, nr,
					in_value_p, in_nr);
}

/**
 * Show the value collected by a port (from a its connected source) as a string
 * (for instance through configfs)
 *
 * @param port		port to query
 * @param page		buffer to store the value (4 Kbytes size)
 *
 * @return		number of bytes written to buffer, or
 *			negative error code
 */
static inline
ssize_t scheduler_port_show_value(struct scheduler_port *port, char *page)
{
	return scheduler_sink_show_value(&port->sink, page);
}

/**
 * Get the value from the remote peer source of the source connected to a port.
 * If the connected source is itself a port and defines a get_remote_value()
 * method, its get_remote_value() method will be called instead. If not
 * get_remote_value() method is defined, the call will be forwarded down until
 * either a source being not a port is found or a get_remote_value() method is
 * defined.
 *
 * See the definition of port_get_remote_value_t for the descriptions of
 * parameters and return value.
 */
extern port_get_remote_value_t scheduler_port_get_remote_value;

#endif /* __KRG_SCHEDULER_PORT_H__ */
