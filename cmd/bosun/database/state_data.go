package database

import (
	"encoding/json"
	"fmt"
	"time"

	"bosun.org/_third_party/github.com/garyburd/redigo/redis"
	"bosun.org/collect"
	"bosun.org/models"
	"bosun.org/opentsdb"
)

/*
incidentById:{id} - json encoded state. Authoritative source.

lastTouched:{alert} - ZSET of alert key to last touched time stamp
unknown:{alert} - Set of unknown alert keys for alert
unevel:{alert} - Set of unevaluated alert keys for alert

openIncidents - Hash of open incident Ids. Alert Key -> incident id
incidents:{ak} - List of incidents for alert key
*/

const (
	statesOpenIncidentsKey = "openIncidents"
)

func statesLastTouchedKey(alert string) string {
	return fmt.Sprintf("lastTouched:%s", alert)
}
func statesUnknownKey(alert string) string {
	return fmt.Sprintf("unknown:%s", alert)
}
func statesUnevalKey(alert string) string {
	return fmt.Sprintf("uneval:%s", alert)
}
func incidentStateKey(id int64) string {
	return fmt.Sprintf("incidentById:%d", id)
}
func incidentsForAlertKeyKey(ak models.AlertKey) string {
	return fmt.Sprintf("incidents:%s", ak)
}

type StateDataAccess interface {
	TouchAlertKey(ak models.AlertKey, t time.Time) error
	GetUntouchedSince(alert string, time int64) ([]models.AlertKey, error)

	GetOpenIncident(ak models.AlertKey) (*models.IncidentState, error)
	GetAllOpenIncidents() ([]*models.IncidentState, error)
	GetIncidentState(incidentId int64) (*models.IncidentState, error)
	UpdateIncidentState(s *models.IncidentState) error
}

func (d *dataAccess) State() StateDataAccess {
	return d
}

func (d *dataAccess) TouchAlertKey(ak models.AlertKey, t time.Time) error {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "TouchAlertKey"})()
	conn := d.GetConnection()
	defer conn.Close()

	_, err := conn.Do("ZADD", statesLastTouchedKey(ak.Name()), t.UTC().Unix(), string(ak))
	return err
}

func (d *dataAccess) GetUntouchedSince(alert string, time int64) ([]models.AlertKey, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetUntouchedSince"})()
	conn := d.GetConnection()
	defer conn.Close()

	results, err := redis.Strings(conn.Do("ZRANGEBYSCORE", statesLastTouchedKey(alert), "-inf", time))
	if err != nil {
		return nil, err
	}
	aks := make([]models.AlertKey, len(results))
	for i := range results {
		aks[i] = models.AlertKey(results[i])
	}
	return aks, nil
}

func (d *dataAccess) GetOpenIncident(ak models.AlertKey) (*models.IncidentState, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetOpenIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	// Get latest incident for alert key and see if it is open
	id, err := redis.Int64(conn.Do("LINDEX", incidentsForAlertKeyKey(ak), 0))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}
	inc, err := d.getIncident(id, conn)
	if err != nil {
		return nil, err
	}
	if inc.Open {
		return inc, nil
	}
	return nil, nil
}

func (d *dataAccess) GetAllOpenIncidents() ([]*models.IncidentState, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetAllOpenIncidents"})()
	conn := d.GetConnection()
	defer conn.Close()

	// get open ids
	vals, err := redis.Values(conn.Do("SMEMBERS", statesOpenIncidentsKey))
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	if err = redis.ScanSlice(vals, &ids); err != nil {
		return nil, err
	}

	// get all incident json keys
	args := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		args = append(args, incidentStateKey(id))
	}
	jsons, err := redis.Strings(conn.Do("MGET", args...))
	if err != nil {
		return nil, err
	}
	results := make([]*models.IncidentState, 0, len(jsons))
	for _, j := range jsons {
		state := &models.IncidentState{}
		if err = json.Unmarshal([]byte(j), state); err != nil {
			return nil, err
		}
		results = append(results, state)
	}
	return results, nil
}

func (d *dataAccess) getIncident(incidentId int64, conn redis.Conn) (*models.IncidentState, error) {
	b, err := redis.Bytes(conn.Do("GET", incidentStateKey(incidentId)))
	if err != nil {
		return nil, err
	}
	state := &models.IncidentState{}
	if err = json.Unmarshal(b, state); err != nil {
		return nil, err
	}
	return state, nil
}

func (d *dataAccess) GetIncidentState(incidentId int64) (*models.IncidentState, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetIncident"})()
	conn := d.GetConnection()
	defer conn.Close()
	return d.getIncident(incidentId, conn)
}

func (d *dataAccess) UpdateIncidentState(s *models.IncidentState) error {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "UpdateIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	return d.transact(conn, func() error {
		//if id is still zero, assign new id.
		if s.Id == 0 {
			id, err := redis.Int64(conn.Do("INCR", "maxIncidentId"))
			if err != nil {
				return err
			}
			s.Id = id
			// add to list for incident
			_, err = conn.Do("LPUSH", incidentsForAlertKeyKey(s.AlertKey), s.Id)
			if err != nil {
				return err
			}
		}

		// store the incident json
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, err = conn.Do("SET", incidentStateKey(s.Id), data)

		addRem := func(b bool) string {
			if b {
				return "SADD"
			}
			return "SREM"
		}
		// appropriately add or remove it from the "open" set
		if _, err = conn.Do(addRem(s.Open), statesOpenIncidentsKey, s.Id); err != nil {
			return err
		}
		//appropriately add or remove from unknown and uneval sets
		if _, err = conn.Do(addRem(s.CurrentStatus == models.StUnknown), statesUnknownKey(s.Alert), s.AlertKey); err != nil {
			return err
		}
		if _, err = conn.Do(addRem(s.Unevaluated), statesUnevalKey(s.Alert), s.AlertKey); err != nil {
			return err
		}
		return nil
	})
}

func (d *dataAccess) transact(conn redis.Conn, f func() error) error {
	if d.isRedis {
		return f()
	}
	if _, err := conn.Do("MULTI"); err != nil {
		return err
	}
	if err := f(); err != nil {
		return err
	}
	if _, err := conn.Do("EXEC"); err != nil {
		return err
	}
	return nil
}
