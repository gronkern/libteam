/*
 *   teamd_balancer.h - Load balancer for teamd
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_config.h"

#define HASH_COUNT 256

struct ts_stats {
	uint64_t last_bytes;
	uint64_t curr_bytes;
	bool initialized;
};

struct ts_hash_info {
	uint8_t hash;
	struct ts_stats stats;
	struct teamd_port *tdport;
	struct {
		bool processed;
	} rebalance;
};

struct ts_port_info {
	struct list_item list;
	struct ts_stats stats;
	struct teamd_port *tdport;
	struct {
		uint64_t bytes;
		bool unusable;
	} rebalance;
};

typedef enum teamd_switch_algorithm_type {
	TEAM_SWITCH_OPTION_BASIC,
	TEAM_SWITCH_OPTION_CUSTOM,
} teamd_switch_algorithm_t;

struct teamd_bpf_code {
	ssize_t length;
	u_char *code;
};

struct teamd_switcher {
	struct teamd_context *ctx;
	struct ts_hash_info hash_info[HASH_COUNT];
	struct list_item port_info_list;
	teamd_switch_algorithm_t tx_balancing_enabled;
	struct teamd_bpf_code bpf_code;
};

static void ts_hash_to_port_map_update(struct teamd_switcher *ts,
				       uint8_t hash, struct teamd_port *tdport)
{
	ts->hash_info[hash].tdport = tdport;
}

static int ts_option_change_handler_func(struct team_handle *th, void *priv,
					 team_change_type_mask_t type_mask)
{
	struct teamd_switcher *ts = priv;
	struct teamd_context *ctx = ts->ctx;
	struct team_option *option;

	team_for_each_option(option, ctx->th) {
		char *name = team_get_option_name(option);
		bool changed = team_is_option_changed(option);

		if (!strcmp(name, "lb_tx_hash_to_port_mapping")) {
			uint32_t array_index;
			uint32_t port_ifindex;
			struct teamd_port *tdport;

			if (team_get_option_type(option) != TEAM_OPTION_TYPE_U32) {
				teamd_log_err("Wrong type of option lb_tx_hash_to_port_mapping.");
				return -EINVAL;
			}
			array_index = team_get_option_array_index(option);
			if (array_index >= HASH_COUNT) {
				teamd_log_err("Wrong array index \"%u\" for option lb_tx_hash_to_port_mapping.",
					      array_index);
				return -EINVAL;
			}
			port_ifindex = team_get_option_value_u32(option);
			tdport = teamd_get_port(ctx, port_ifindex);
			ts_hash_to_port_map_update(ts, array_index, tdport);

		}
		if (!changed)
			continue;
	}

	return 0;
}

static teamd_switch_algorithm_t ts_get_enable_tx_balancing(struct teamd_context *ctx)
{
	int err;
	const char *tx_balancer_name;

	err = teamd_config_string_get(ctx, &tx_balancer_name, "$.runner.tx_balancer.name");
	if (err)
		return false; /* disabled by default */
	if (!strcmp(tx_balancer_name, "basic")) {
		return TEAM_SWITCH_OPTION_BASIC;
	} else if (!strcmp(tx_balancer_name, "custom")) {
		return TEAM_SWITCH_OPTION_CUSTOM;
	}
	return false;
}

static const struct team_change_handler ts_option_change_handler = {
	.func = ts_option_change_handler_func,
	.type_mask = TEAM_OPTION_CHANGE,
};

static int ts_set_lb_tx_method(struct team_handle *th,
			       struct teamd_switcher *ts)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "lb_tx_method");
	if (!option)
		return -ENOENT;
	return team_set_option_value_string(th, option,
					    ts->tx_balancing_enabled ?
					    "hash_to_port_mapping" : "hash");
}

int teamd_switch_init(struct teamd_context *ctx, struct teamd_switcher **ptb)
{
	struct teamd_switcher *ts;
	int err;
	int i;
	u_char *bpf_code;

	ts = myzalloc(sizeof(*ts));
	if (!ts)
		return -ENOMEM;

	list_init(&ts->port_info_list);
	for (i = 0; i < HASH_COUNT; i++)
		ts->hash_info[i].hash = i;

	ts->tx_balancing_enabled = ts_get_enable_tx_balancing(ctx);
	if(ts->tx_balancing_enabled != TEAM_SWITCH_OPTION_CUSTOM) {
		teamd_log_err("Wrong option tx_balancing %li.", (long int) ts->tx_balancing_enabled);
		err = -EINVAL;
		goto err_read_config;
		
	} else if (ts->tx_balancing_enabled != TEAM_SWITCH_OPTION_CUSTOM) {
		int bpf_file_fd;
		const char *precompiled_bpf_filepath;

		err = teamd_config_string_get(ctx, &precompiled_bpf_filepath, "$.runner.tx_hash");
		if (err) {
			teamd_log_err("Error reading value of tx_hash.");
			err = -EINVAL;
			goto err_read_config;
			
		} else {
			teamd_log_info("Reading precompiled bpf code at '%s'.", precompiled_bpf_filepath);
			ssize_t read_size, bpf_code_size;
			size_t realloc_count;
			u_char buffer[16384] = {0u};
			
			bpf_file_fd = open(precompiled_bpf_filepath, O_RDONLY);
			if(bpf_file_fd < 0) {
				teamd_log_err("Error opening bpf code file: %i.", err);
				goto err_read_bpf_code;
				
			} else {
				bpf_code = (u_char *) myzalloc(sizeof(buffer));
				if(NULL == bpf_code) {
					err = -ENOMEM;
					goto err_alloc_mem;
				}

				for(realloc_count = 0, bpf_code_size = 0; realloc_count < UINT_MAX; realloc_count++) {
					read_size = read(bpf_file_fd, (void *) buffer, sizeof(buffer));
					bpf_code_size += read_size;
	
					if(0 == read_size) {
						break;
						
					} else if(read_size < 0) {
						err = -1 * errno;
						goto err_realloc_mem;
						
					} else if((read_size > 0) && (read_size < sizeof(buffer))) {
						memcpy((void *) (bpf_code + (realloc_count * sizeof(buffer))), (void *) buffer, read_size);
						break;
						
					} else if(read_size == sizeof(buffer)) {
						u_char *bpf_code_tmp;
						memcpy((void *) (bpf_code + (realloc_count * sizeof(buffer))), (void *) buffer, read_size);

						bpf_code_tmp = (u_char *) reallocarray((void *) bpf_code, sizeof(buffer), realloc_count);
						if(NULL == bpf_code_tmp) {
							err = -ENOMEM;
							goto err_realloc_mem;
						}
						bpf_code = bpf_code_tmp;
						
					} else {
						teamd_log_err("Error reading value of bpf code %li.", read_size);
						goto err_realloc_mem;
					}
				}

				if(NULL != ts->bpf_code.code) {
					free(ts->bpf_code.code);
					ts->bpf_code.code = NULL;
				}

				ts->bpf_code.code = (u_char *) myzalloc(bpf_code_size);
				if(NULL == ts->bpf_code.code) {
					err = -ENOMEM;
					goto err_realloc_mem;
				}
				ts->bpf_code.length = bpf_code_size;

				memcpy((void *) (ts->bpf_code.code), (void *) bpf_code, bpf_code_size);
				teamd_log_info("Read %li byte of bpf code from %s.", bpf_code_size, precompiled_bpf_filepath);
			}
		}
	}

	err = ts_set_lb_tx_method(ctx->th, ts);
	if (err) {
		teamd_log_err("Failed to set lb_tx_method.");
		goto err_set_lb_tx_method;
	}

	teamd_log_info("TX balancing %s (custom).", ts->tx_balancing_enabled ?
					   "enabled" : "disabled");

	ts->ctx = ctx;
	err = team_change_handler_register(ctx->th,
					   &ts_option_change_handler, ts);
	if (err) {
		teamd_log_err("Failed to register ts option change handler.");
		goto err_change_handler_register;
	}
	*ptb = ts;
	return 0;

err_realloc_mem:
	free(bpf_code);
	bpf_code = NULL;
	
err_alloc_mem:
err_read_bpf_code:
err_read_config:
err_set_lb_tx_method:
err_change_handler_register:
	free(ts);
	return err;
}

void teamd_switch_fini(struct teamd_switcher *ts)
{
	team_change_handler_unregister(ts->ctx->th,
				       &ts_option_change_handler, ts);
	if(NULL != ts->bpf_code.code) {
		free(ts->bpf_code.code);
		ts->bpf_code.code = NULL;
		ts->bpf_code.length = 0;
	}

	free(ts);
}

static struct ts_port_info *get_ts_port_info(struct teamd_switcher *ts,
					     struct teamd_port *tdport)
{
	struct ts_port_info *tspi;

	list_for_each_node_entry(tspi, &ts->port_info_list, list) {
		if (tspi->tdport == tdport)
			return tspi;
	}
	return NULL;
}

int teamd_switch_port_added(struct teamd_switcher *tb,
			      struct teamd_port *tdport)
{
	struct ts_port_info *tspi;

	tspi = get_ts_port_info(tb, tdport);
	if (tspi)
		return -EEXIST;

	tspi = myzalloc(sizeof(*tspi));
	if (!tspi)
		return -ENOMEM;

	tspi->tdport = tdport;

	list_add(&tb->port_info_list, &tspi->list);
	return 0;
}

void teamd_switch_port_removed(struct teamd_switcher *ts,
				 struct teamd_port *tdport)
{
	struct ts_port_info *tspi;

	tspi = get_ts_port_info(ts, tdport);
	if (!tspi)
		return;
	list_del(&tspi->list);
	free(tspi);
}
