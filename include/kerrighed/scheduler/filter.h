#ifndef __KRG_SCHEDULER_FILTER_H__
#define __KRG_SCHEDULER_FILTER_H__

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/types.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/scheduler/port.h>

/*
 * A filter is a scheduler_port having a source. A filter collects data/events
 * from a source connected to its sink, and generates data/events related to
 * what it collects. Filters sources are connected to scheduler_ports when doing
 * mkdir in ports directories, and filters sinks are connected to lower sources
 * the same way as ports.
 *
 * A filter can block update propagation as well generating updates.
 *
 * A filter can modify the value of the source it is connected to when the sink
 * it is connected to requests its value, as well as providing values generated
 * by other means.
 */

/* Structure representing a filter */
struct scheduler_filter {
	struct scheduler_source source;
	struct scheduler_port port;
};

#define SCHEDULER_FILTER_ATTR_SIZE SCHEDULER_PORT_ATTR_SIZE

/*
 * Structure representing a filter attribute
 * Just an API translation from  port attributes
 */
struct scheduler_filter_attribute {
	struct scheduler_port_attribute port_attr;
};

/*
 * Convenience macros to define a scheduler_filter_attribute
 *
 * These convenience macros should be used the following way:
 *
 * First, implemented methods must be defined using the
 * DEFINE_SCHEDULER_FILTER_ATTRIBUTE_<method> macros. Second, the
 * scheduler_filter_attribute must be filled using
 * {BEGIN,END}_SCHEDULER_FILTER_ATTRIBUTE and SCHEDULER_FILTER_ATTRIBUTE_*
 * macros:
 *
 *	BEGIN_SCHEDULER_FILTER_ATTRIBUTE(var_name, name, mode),
 * if needed:
 *		.SCHEDULER_FILTER_ATTRIBUTE_<method>(name),
 *		...
 * and finally:
 *	END_SCHEDULER_FILTER_ATTRIBUTE(name);
 */

/**
 * Convenience macro to start the definition of a
 * scheduler_filter_attribute. The definition must end with
 * END_SCHEDULER_FILTER_ATTRIBUTE(name).
 *
 * @param var_name	name of the scheduler_filter_attribute variable
 * @param name		name of the attribute entry in the filter directory
 * @param mode		access mode of the attribute entry
 */
#define BEGIN_SCHEDULER_FILTER_ATTRIBUTE(var_name, name, mode)		\
	struct scheduler_filter_attribute var_name = {			\
		.port_attr = SCHEDULER_PORT_ATTRIBUTE_INIT(#name, mode,	\
							   NULL, NULL)

/**
 * Convenience macro to attach a previously defined show() method to a
 * scheduler_filter_attribute. The show() method must have been defined earlier
 * with DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_ATTRIBUTE
 */
#define SCHEDULER_FILTER_ATTRIBUTE_SHOW(name)	\
	port_attr.show = name##_port_attr_show

/**
 * Convenience macro to attach a previously defined store() method to a
 * scheduler_filter_attribute. The store() method must have been defined earlier
 * with DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_ATTRIBUTE
 */
#define SCHEDULER_FILTER_ATTRIBUTE_STORE(name)		\
	port_attr.store = name##_port_attr_store

/**
 * End the definition of a scheduler_filter_attribute. Must close any
 * BEGIN_SCHEDULER_FILTER_ATTRIBUTE section.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_ATTRIBUTE
 */
#define END_SCHEDULER_FILTER_ATTRIBUTE(name)	\
	}

/**
 * Convenience macro to define an show() method for a filter attribute. The
 * method will be called name_show.
 *
 * @param name		name of the filter attribute
 * @param filter	filter which attribute is read
 * @param attr		scheduler_filter_attribute describing the attribute
 * @param page		4Kbytes buffer to fill in
 */
#define DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(name, filter, attr, page)    \
	static ssize_t name##_show(struct scheduler_filter *,		    \
				   struct scheduler_filter_attribute *,     \
				   char *);				    \
	static ssize_t name##_port_attr_show(				    \
		struct scheduler_port *port,				    \
		struct scheduler_port_attribute *port_attr, char *page)	    \
	{								    \
		return name##_show(					    \
			container_of(port, struct scheduler_filter, port),  \
			container_of(port_attr,				    \
				     struct scheduler_filter_attribute,     \
				     port_attr),			    \
			page);						    \
	}								    \
	static ssize_t name##_show(struct scheduler_filter *filter,	    \
				   struct scheduler_filter_attribute *attr, \
				   char *page)

/**
 * Convenience macro to define an store() method for a filter attribute. The
 * method will be called name_store.
 *
 * @param name		name of the filter attribute
 * @param filter	filter which attribute is to be modified
 * @param attr		scheduler_filter_attribute describing the attribute
 * @param page		buffer containing the data to modify attribute
 * @param count		number of bytes contained in buffer
 */
#define DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(name, filter, attr,	     \
						page, count)		     \
	static ssize_t name##_store(struct scheduler_filter *,		     \
				   struct scheduler_filter_attribute *,      \
				   const char *, size_t);		     \
	static ssize_t name##_port_attr_store(				     \
		struct scheduler_port *port,				     \
		struct scheduler_port_attribute *port_attr,		     \
		const char *page, size_t count)				     \
	{								     \
		return name##_store(					     \
			container_of(port, struct scheduler_filter, port),   \
			container_of(port_attr,				     \
				     struct scheduler_filter_attribute,      \
				     port_attr),			     \
			page, count);					     \
	}								     \
	static ssize_t name##_store(struct scheduler_filter *filter,	     \
				    struct scheduler_filter_attribute *attr, \
				    const char *page, size_t count)

/* End of convenience macros */

/*
 * Structure describing a type of filter. Filter of this type can be created
 * once the type is registered.
 */
struct scheduler_filter_type {
	struct scheduler_source_type source_type;
	struct scheduler_port_type port_type;
	struct scheduler_filter_attribute **attrs;
};

/**
 * Mandatory macro to define a scheduler_filter_type. Can be used through the
 * BEGIN_SCHEDULER_FILTER_TYPE helper.
 *
 * @param filter_type	variable name of the filter type
 * @param owner		module providing this type
 * @param name		unique name among scheduler_port_type names
 * @param new		port_type constructor for this filter type
 * @param destroy	port_type destructor for this filter type
 * @param get_value	(source) callback to get the filtered value
 * @param update_value	(sink) callback called when the source of a filter of
 *			this type notifies an update
 * @param show_value	(source) callback to show the value filtered by a filter
 *			of this type
 * @param get_remote_value
 *			(port) callback to get a remote filtered value
 * @param src_value_type
 *			string containing the type name of filter's values
 * @param src_value_type_size
 *			size in bytes of a src_value_type value
 * @param src_get_param_type
 *			string containing the type name of the parameters for
 *			the filter's get_value method, or NULL
 * @param src_get_param_type_size
 *			size in bytes of a src_get_param_type parameter
 * @param snk_value_type
 *			string containing the type name of lower source's values
 * @param snk_value_type_size
 *			size in bytes of a snk_value_type value
 * @param snk_get_param_type
 *			string containing the type name of the parameters for
 *			the sink's get_value calls, or NULL
 * @param snk_get_param_type_size
 *			size in bytes of a snk_get_param_type parameter
 * @param _attrs	NULL-terminated array of custom
 *			scheduler_filter_attributes, or NULL
 */
#define SCHEDULER_FILTER_TYPE_INIT(filter_type, owner, name,		\
				   new, destroy,			\
				   get_value, update_value, show_value, \
				   get_remote_value,			\
				   src_value_type,			\
				   src_value_type_size,			\
				   src_get_param_type,			\
				   src_get_param_type_size,		\
				   snk_value_type,			\
				   snk_value_type_size,			\
				   snk_get_param_type,			\
				   snk_get_param_type_size,		\
				   _attrs)				\
	{								\
		.source_type =						\
			SCHEDULER_SOURCE_TYPE_INIT(get_value, show_value, \
						   src_value_type,	\
						   src_value_type_size, \
						   src_get_param_type,	\
						   src_get_param_type_size), \
		.port_type =						\
			SCHEDULER_PORT_TYPE_INIT(filter_type.port_type, \
						 owner, name,		\
						 update_value,		\
						 snk_value_type,	\
						 snk_value_type_size,	\
						 snk_get_param_type,	\
						 snk_get_param_type_size, \
						 &filter_type.source_type, \
						 get_remote_value,	\
						 new, destroy),		\
		.attrs = _attrs,					\
	}

/*
 * Convenience macros to define a scheduler_filter_type
 *
 * These convenience macros should be used the following way:
 *
 * First, implemented methods must be defined using the
 * DEFINE_SCHEDULER_FILTER_<method> macros. Second, the scheduler_filter_type
 * must be filled using {BEGIN,END}_SCHEDULER_FILTER_TYPE and SCHEDULER_FILTER_*
 * macros:
 *
 *	BEGIN_SCHEDULER_FILTER_TYPE(name),
 *		.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(name, type),
 *		.SCHEDULER_FILTER_PORT_VALUE_TYPE(name, type),
 * if needed:
 *		.SCHEDULER_FILTER_<method>(name),
 *		.SCHEDULER_FILTER_SOURCE_PARAM_TYPE(name, type),
 *		.SCHEDULER_FILTER_PORT_PARAM_TYPE(name, type),
 *		.SCHEDULER_FILTER_ATTRS(name, attrs),
 *		...
 * and finally:
 *	END_SCHEDULER_FILTER_TYPE(name);
 */

/**
 * Convenience macro to start the definition of a scheduler_filter_type. The
 * definition must end with END_SCHEDULER_FILTER_TYPE(name). The variable will
 * be called name_type.
 *
 * @param name		name of the scheduler_filter type
 */
#define BEGIN_SCHEDULER_FILTER_TYPE(name)			   \
	struct scheduler_filter_type name##_type = {		   \
		.source_type = SCHEDULER_SOURCE_TYPE_INIT(	   \
			scheduler_filter_simple_source_get_value,  \
			scheduler_filter_simple_source_show_value, \
			NULL, 0, NULL, 0),			   \
		.port_type = SCHEDULER_PORT_TYPE_INIT(		   \
			name##_type.port_type, THIS_MODULE, #name, \
			scheduler_filter_simple_sink_update_value, \
			NULL, 0, NULL, 0,			   \
			&name##_type.source_type,		   \
			scheduler_port_get_remote_value,	   \
			name##_port_new, name##_port_destroy)

/**
 * Convenience macro to attach a previously defined get_value() method to a
 * scheduler_filter type. The get_value() method must have been defined earlier
 * with DEFINE_SCHEDULER_FILTER_GET_VALUE(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 */
#define SCHEDULER_FILTER_GET_VALUE(name)				    \
	__SCHEDULER_SOURCE_GET_VALUE(source_type., name##_source_get_value)

/**
 * Convenience macro to attach a previously defined update_value() method to a
 * scheduler_filter type. The update_value() method must have been defined earlier
 * with DEFINE_SCHEDULER_FILTER_UPDATE_VALUE(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 */
#define SCHEDULER_FILTER_UPDATE_VALUE(name)			\
	__SCHEDULER_PORT_UPDATE_VALUE(port_type., name##_port)

/**
 * Convenience macro to attach a previously defined show_value() method to a
 * scheduler_filter type. The show_value() method must have been defined earlier
 * with DEFINE_SCHEDULER_FILTER_SHOW_VALUE(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 */
#define SCHEDULER_FILTER_SHOW_VALUE(name)				      \
	__SCHEDULER_SOURCE_SHOW_VALUE(source_type., name##_source_show_value)

/**
 * Convenience macro to attach a previously defined get_remote_value() method to
 * a scheduler_filter type. The get_remote_value() method must have been defined
 * earlier with DEFINE_SCHEDULER_FILTER_GET_REMOTE_VALUE(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 */
#define SCHEDULER_FILTER_GET_REMOTE_VALUE(name)				\
	__SCHEDULER_PORT_GET_REMOTE_VALUE(port_type., name##_port)

/**
 * Convenience macro to declare the value type generated by a scheduler
 * filter. Must be used within all BEGIN_SCHEDULER_FILTER_TYPE sections.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 * @param type		litteral expression of the value type output by the
 *			source
 */
#define SCHEDULER_FILTER_SOURCE_VALUE_TYPE(name, type)		\
	__SCHEDULER_SOURCE_VALUE_TYPE(source_type., type)

/**
 * Convenience macro to declare the parameter type of the get_value() method of
 * a filter's source.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 * @param type		litteral expression of the parameter type
 */
#define SCHEDULER_FILTER_SOURCE_PARAM_TYPE(name, type)		\
	__SCHEDULER_SOURCE_PARAM_TYPE(source_type., type)

/**
 * Convenience macro to declare the value type collected by a scheduler
 * filter. Must be used within all BEGIN_SCHEDULER_FILTER_TYPE sections.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 * @param type		litteral expression of the value type read by the sink
 */
#define SCHEDULER_FILTER_PORT_VALUE_TYPE(name, type)			\
	__SCHEDULER_PORT_VALUE_TYPE(port_type., name##_port, type)

/**
 * Convenience macro to declare the parameter type used when calling the
 * get_value() method of a connected source.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 * @param type		litteral expression of the parameter type
 */
#define SCHEDULER_FILTER_PORT_PARAM_TYPE(name, type)			\
	__SCHEDULER_PORT_PARAM_TYPE(port_type., name##_port, type)

/**
 * Convenience macro to attach custom filter attributes to a filter type.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 * @param attrs		NULL terminated array of pointers to custom filter
 *			attributes (struct scheduler_filter_attribute)
 */
#define SCHEDULER_FILTER_ATTRIBUTES(name, _attrs)	\
	attrs = _attrs

/**
 * End the definition of a scheduler_filter_type. Must close any
 * BEGIN_SCHEDULER_FILTER_TYPE section.
 *
 * @param name		must match the name used with
 *			BEGIN_SCHEDULER_FILTER_TYPE
 */
#define END_SCHEDULER_FILTER_TYPE(name)		\
	}

/**
 * Convenience macro to define a typed get_value method with no parameter.
 * The typed method will be called name_get_value
 *
 * @param name		name of the filter type
 * @param filter	name of the struct filter *arg of the method
 * @param type		type of the values output by the filter (eg. int)
 * @param ptr		name of the type *arg of the method
 * @param nr		name of the array length arg of the method
 */
#define DEFINE_SCHEDULER_FILTER_GET_VALUE(name, filter, type, ptr, nr)	       \
	static int name##_get_value(struct scheduler_filter *,		       \
				    type *, unsigned int);		       \
	static int name##_source_get_value(struct scheduler_source *source,    \
					   void *__ptr, unsigned int __nr,     \
					   const void *__in_ptr,	       \
					   unsigned int __in_nr)	       \
	{								       \
		if (!__nr)						       \
			return 0;					       \
		return name##_get_value(				       \
			container_of(source, struct scheduler_filter, source), \
			__ptr, __nr);					       \
	}								       \
	static int name##_get_value(struct scheduler_filter *filter,	       \
				    type *ptr, unsigned int nr)

/**
 * Convenience macro to define a typed get_value() method with parameters.
 * The typed method will be called name_get_value
 *
 * @param name		name of the filter type
 * @param filter	name of the struct filter *arg of the method
 * @param type		type of the values output by the filter (eg. int)
 * @param ptr		name of the type *arg of the method
 * @param nr		name of the array length parameter of the method
 * @param in_type	type of the parameters of the method (eg. int)
 * @param in_ptr	name of the in_type *arg of the method
 * @param in_nr		name of the parameters array length arg of the method
 */
#define DEFINE_SCHEDULER_FILTER_GET_VALUE_WITH_INPUT(name, filter,	       \
						     type, ptr, nr,	       \
						     in_type, in_ptr, in_nr)   \
	static int name##_get_value(struct scheduler_filter *,		       \
				    type *, unsigned int,		       \
				    const in_type *, unsigned int);	       \
	static int name##_source_get_value(struct scheduler_source *source,    \
					   void *__ptr, unsigned int __nr,     \
					   const void *__in_ptr,	       \
					   unsigned int __in_nr)	       \
	{								       \
		return name##_get_value(				       \
			container_of(source, struct scheduler_filter, source), \
			__ptr, __nr, __in_ptr, __in_nr);		       \
	}								       \
	static int name##_get_value(struct scheduler_filter *filter,	       \
				    type *ptr, unsigned int nr,		       \
				    const in_type *in_ptr,		       \
				    unsigned int in_nr)

/**
 * Convenience macro to define a show_value() method.
 * The method will be called name_show_value
 *
 * @param name		name of the filter type
 * @param filter	name of the struct filter *arg of the method
 * @param page		name of the buffer arg of the method
 */
#define DEFINE_SCHEDULER_FILTER_SHOW_VALUE(name, filter, page)		       \
	static ssize_t name##_show_value(struct scheduler_filter *filter,      \
					 char *page);			       \
	static ssize_t name##_source_show_value(			       \
		struct scheduler_source *source,			       \
		char *page)						       \
	{								       \
		return name##_show_value(				       \
			container_of(source, struct scheduler_filter, source), \
			page);						       \
	}								       \
	static ssize_t name##_show_value(struct scheduler_filter *filter,      \
					 char *page)

/**
 * Convenience macro to define a update_value() method.
 * The method will be called name_update_value
 *
 * @param name		name of the filter type
 * @param filter	name of the struct filter *arg of the method
 */
#define DEFINE_SCHEDULER_FILTER_UPDATE_VALUE(name, filter)		   \
	static void name##_update_value(struct scheduler_filter *);	   \
	static void name##_port_sink_update_value(			   \
		struct scheduler_sink *sink,				   \
		struct scheduler_source *source)			   \
	{								   \
		name##_update_value(					   \
			container_of(sink,				   \
				     struct scheduler_filter, port.sink)); \
	}								   \
	static void name##_update_value(struct scheduler_filter *filter)

/**
 * Convenience macro to define a typed get_remote_value() method with
 * parameters.  The typed method will be called name_get_remote_value
 *
 * @param name		name of the filter type
 * @param filter	name of the struct filter *arg of the method
 * @param node		name of the node arg of the method
 * @param type		type of the values output by the filter (eg. int)
 * @param ptr		name of the type *arg of the method
 * @param nr		name of the array length parameter of the method
 * @param in_type	type of the parameters of the method (eg. int)
 * @param in_ptr	name of the in_type *arg of the method
 * @param in_nr		name of the parameters array length arg of the method
 */
#define DEFINE_SCHEDULER_FILTER_GET_REMOTE_VALUE(name, filter, node,	     \
						 type, ptr, nr,		     \
						 in_type, in_ptr, in_nr)     \
	static int name##_get_remote_value(struct scheduler_filter *filter,  \
					   kerrighed_node_t node,	     \
					   type *ptr, unsigned int nr,	     \
					   const in_type *in_ptr,	     \
					   unsigned int in_nr);		     \
	static int name##_port_get_remote_value(struct scheduler_port *port, \
						kerrighed_node_t node,	     \
						void *__ptr,		     \
						unsigned int __nr,	     \
						const void *__in_ptr,	     \
						unsigned int __in_nr)	     \
	{								     \
		return name##_get_remote_value(				     \
			container_of(port, struct scheduler_filter, port),   \
			node,						     \
			__ptr, __nr, __in_ptr, __in_nr);		     \
	}								     \
	static int name##_get_remote_value(struct scheduler_filter *filter,  \
					   kerrighed_node_t node,	     \
					   type *ptr, unsigned int nr,	     \
					   const in_type *in_ptr,	     \
					   unsigned int in_nr)

/**
 * Convenience macro to define the mandatory constructor for a filter type. The
 * method will be called name_new
 *
 * @param name		name of the filter type
 * @param fname		configfs entry name of the new filter
 */
#define DEFINE_SCHEDULER_FILTER_NEW(name, fname)			  \
	static struct scheduler_filter *name##_new(const char *);	  \
	static struct scheduler_port *name##_port_new(const char *fname)  \
	{								  \
		return &name##_new(fname)->port;			  \
	}								  \
	static struct scheduler_filter *name##_new(const char *fname)

/**
 * Convenience macro to define the mandatory destructor for a filter type. The
 * method will be called name_destroy
 *
 * @param name		name of the filter type
 * @param filter	filter to destroy
 */
#define DEFINE_SCHEDULER_FILTER_DESTROY(name, filter)			    \
	static void name##_destroy(struct scheduler_filter *);		    \
	static void name##_port_destroy(struct scheduler_port *port)	    \
	{								    \
		name##_destroy(						    \
			container_of(port, struct scheduler_filter, port)); \
	}								    \
	static void name##_destroy(struct scheduler_filter *filter)

/* End of convenience macros */

/**
 * Register a new filter type
 *
 * @param type		type initialized with SCHEDULER_FILTER_TYPE[_INIT] to
 *			register
 *
 * @return		0 is successful,
 *			-EINVAL if the type is not complete,
 *			-ENOMEM if not sufficient memory could be allocated,
 *			-EEXIST if a filter type of the same name is already
 *			registered
 */
int scheduler_filter_type_register(struct scheduler_filter_type *type);
/**
 * Unregister a filter type. Must *only* be called at module unloading.
 *
 * @param type		The filter type to unregister
 */
void scheduler_filter_type_unregister(struct scheduler_filter_type *type);

/**
 * Initialize a scheduler_filter. Must be called by filter constructors.
 *
 * @param filter	filter to initialize
 * @param name		name of the new filter. Must match the name given as
 *			argument to the constructor.
 * @param type		type of the new filter
 * @param default_groups
 *			NULL terminated array of custom config_groups displayed
 *			as subdirs of the filter, or NULL
 *
 * @return		0 if successful,
 *			-ENODEV if the type is not registered
 */
int scheduler_filter_init(struct scheduler_filter *filter,
			  const char *name,
			  struct scheduler_filter_type *type,
			  struct config_group **default_groups);
/**
 * Cleanup a scheduler filter. Must be called by the filter destructor.
 *
 * @param filter	filter to cleanup
 */
void scheduler_filter_cleanup(struct scheduler_filter *filter);

/**
 * Get a reference on a filter.
 *
 * @param filter	filter to get the reference on
 */
static inline void scheduler_filter_get(struct scheduler_filter *filter)
{
	config_group_get(&filter->port.pipe.config);
}

/**
 * Put a reference on a filter.
 *
 * @param filter	filter to put the reference on
 */
static inline void scheduler_filter_put(struct scheduler_filter *filter)
{
	config_group_put(&filter->port.pipe.config);
}

/**
 * Lock a filter. This will *not* prevent the scheduler_pipe subsystem from
 * calling update_value and show_value callbacks. This will however block
 * subscription/unsubscription of sinks to this filter.
 *
 * @param filter	filter to lock
 */
static inline void scheduler_filter_lock(struct scheduler_filter *filter)
{
	scheduler_source_lock(&filter->source);
}

/**
 * Unlock a filter.
 *
 * @param filter	filter to unlock
 */
static inline void scheduler_filter_unlock(struct scheduler_filter *filter)
{
	scheduler_source_unlock(&filter->source);
}

/* Trivial get_value method for a scheduler_filter */
extern source_get_value_t scheduler_filter_simple_source_get_value;

/**
 * Get the value from the source connected to a filter
 *
 * @param filter	filter to query
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			negative error code
 */
static inline
int
scheduler_filter_simple_get_value_with_input(struct scheduler_filter *filter,
					     void *value_p, int nr_value,
					     void *param_p, int nr_param)
{
	/*
	 * Optimization: one stack frame less than:
	 * return scheduler_filter_simple_source_get_value(&filter->source,
	 *						   ...);
	 */
	return scheduler_port_get_value(&filter->port,
					value_p, nr_value, param_p, nr_param);
}
/**
 * Get the value from the source connected to a filter without parameter
 *
 * @param filter	filter to query
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 *
 * @return		number of values filled, or
 *			negative error code
 */
static inline
int
scheduler_filter_simple_get_value(struct scheduler_filter *filter,
				  void *value_p, int nr_value)
{
	/*
	 * Optimization: one stack frame less than:
	 * return scheduler_filter_simple_source_get_value(&filter->source,
	 *						   ...);
	 */
	return scheduler_port_get_value(&filter->port,
					value_p, nr_value, NULL, 0);
}

/* Trivial show_value() method for a scheduler_filter */
extern source_show_value_t scheduler_filter_simple_source_show_value;

/**
 * Show the value collected by a filter (from a its connected source) as a string
 * (for instance through configfs)
 *
 * @param filter	filter to query
 * @param page		buffer to store the value (4 Kbytes size)
 *
 * @return		number of bytes written to buffer, or
 *			negative error code
 */
static inline
ssize_t
scheduler_filter_simple_show_value(struct scheduler_filter *filter, char *page)
{
	/*
	 * Optimization: one stack frame less than:
	 * return scheduler_filter_simple_source_show_value(&filter->source,
	 *						    page);
	 */
	return scheduler_port_show_value(&filter->port, page);
}

/* Trivial update_value() method for a filter */
extern sink_update_value_t scheduler_filter_simple_sink_update_value;

/**
 * Propagate a notification to the sink connected to a filter
 *
 * @param filter	filter being notified
 */
static inline
void scheduler_filter_simple_update_value(struct scheduler_filter *filter)
{
	scheduler_filter_simple_sink_update_value(&filter->port.sink, NULL);
}

/**
 * Get the value from the remote peer source of the source connected to a
 * filter. If the connected source is itself a port and defines a
 * get_remote_value() method, its get_remote_value() method will be called
 * instead. If not get_remote_value() method is defined, the call will be
 * forwarded down until either a source being not a port is found or a
 * get_remote_value() method is defined.
 *
 * @param filter	filter querying a remote source
 * @param node		node to get the value from
 * @param value_p	array of values to be filled
 * @param nr_value	max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			-EAGAIN if the request is pending and the caller should
 *			retry later, or
 *			other negative error code
 */
static inline
int
scheduler_filter_simple_get_remote_value(struct scheduler_filter *filter,
					 kerrighed_node_t node,
					 void *value_p, unsigned int nr_value,
					 const void *param_p, unsigned int nr_param)
{
	return scheduler_port_get_remote_value(&filter->port, node,
					       value_p, nr_value,
					       param_p, nr_param);
}

#endif /* __KRG_SCHEDULER_FILTER_H__ */
